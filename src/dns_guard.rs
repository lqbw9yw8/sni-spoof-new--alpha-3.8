//! dns_guard — dynamic Windows Filtering Platform protection for plaintext DNS. [PARTIAL]
//!
//! The port-53 guard is a real user-mode WFP policy on Windows: it opens a
//! dynamic BFE session, permits only the two loopback resolver addresses, and
//! blocks outbound TCP/UDP traffic whose remote port is 53 on both IP stacks.
//! The dynamic session is deliberately owned by [`WfpGuard`], so a normal
//! shutdown *and* a process crash remove the policy instead of leaving a
//! persistent firewall rule behind.
//!
//! This is a packet-blocking policy, not a DNS redirect callout. The legacy
//! `trusted_dns` setting is rejected by `config::Settings::validate`; redirecting
//! packets requires a signed kernel callout that is not shipped here.
#![allow(unsafe_code)]

use crate::error::DpiGuardError;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterSpec {
    pub name: &'static str,
    pub layer: &'static str,
    pub action_block: bool,
    pub remote_port: Option<u16>,
    pub remote_addr: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpSessionSpec {
    pub session_name: &'static str,
    pub dynamic: bool,
}

pub fn init_wfp_hook_spec() -> WfpSessionSpec {
    WfpSessionSpec {
        session_name: "dpi_guard_dns_protect",
        dynamic: true,
    }
}

/// Allow UDP/TCP 53 to 127.0.0.1 (installed above the block filter).
pub fn allow_port_53_localhost_spec() -> WfpFilterSpec {
    WfpFilterSpec {
        name: "allow-dns-localhost",
        layer: "FWPM_LAYER_OUTBOUND_TRANSPORT_V4",
        action_block: false,
        remote_port: Some(53),
        remote_addr: Some(Ipv4Addr::LOCALHOST),
    }
}

/// Block TCP/UDP 53 to every non-loopback remote address.
pub fn block_port_53_spec() -> WfpFilterSpec {
    WfpFilterSpec {
        name: "block-dns",
        layer: "FWPM_LAYER_OUTBOUND_TRANSPORT_V4",
        action_block: true,
        remote_port: Some(53),
        remote_addr: None,
    }
}

/// The pair WFP needs on each IP stack: allow localhost, then block the rest.
pub fn dns_protection_filters() -> Vec<WfpFilterSpec> {
    vec![allow_port_53_localhost_spec(), block_port_53_spec()]
}

/// Back-compat name: the *block* half of the pair.
pub fn block_port_53_except_localhost_spec() -> WfpFilterSpec {
    block_port_53_spec()
}

/// An owned dynamic WFP policy. Dropping it removes all filters and closes the
/// BFE session; the Windows dynamic-session invariant also cleans up after a
/// crash before `Drop` can run.
#[must_use = "dropping WfpGuard removes the DNS policy"]
pub struct WfpGuard {
    #[cfg(windows)]
    inner: wfp::Guard,
}

/// Install the real port-53 policy on Windows.
///
/// This function intentionally fails on Windows when BFE/WFP rejects any
/// operation. The caller must not continue as though DNS protection existed.
/// Non-Windows builds have no WFP engine and return a typed platform error.
pub fn block_port_53_except_localhost() -> Result<WfpGuard, DpiGuardError> {
    #[cfg(windows)]
    {
        wfp::install().map(|inner| WfpGuard { inner })
    }
    #[cfg(not(windows))]
    {
        Err(DpiGuardError::PlatformNotSupported {
            os: std::env::consts::OS,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHijackSpec {
    pub trusted_resolver: Ipv4Addr,
    /// Packet redirect needs a signed WFP callout driver — not this crate.
    pub needs_callout_driver: bool,
}

pub fn hijack_dns_requests_target(trusted_resolver: Ipv4Addr) -> Result<Ipv4Addr, DpiGuardError> {
    hijack_dns_requests_spec(trusted_resolver).map(|s| s.trusted_resolver)
}

pub fn hijack_dns_requests_spec(
    trusted_resolver: Ipv4Addr,
) -> Result<DnsHijackSpec, DpiGuardError> {
    if trusted_resolver.is_loopback() || trusted_resolver.is_unspecified() {
        return Err(DpiGuardError::OutOfRange(
            "trusted resolver must be a real routable address".into(),
        ));
    }
    Ok(DnsHijackSpec {
        trusted_resolver,
        needs_callout_driver: true,
    })
}

// The FFI below intentionally lives in its own module and keeps every raw
// pointer behind the single `install`/`Drop` boundary above. The C layouts are
// the Windows SDK's FWPM_*0 layouts; only the fields needed by these filters
// are represented. Invariants:
//
//  * every pointer passed to BFE points at a live local value for the entire
//    FFI call;
//  * all objects are added in one transaction;
//  * an add/commit failure aborts the transaction before the engine closes;
//  * a successful session is dynamic and is additionally deleted explicitly
//    in Drop for deterministic cleanup.
#[cfg(windows)]
mod wfp {
    use super::DpiGuardError;
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use std::ptr;

    type Handle = *mut c_void;

    const ERROR_SUCCESS: u32 = 0;
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x0000_0001;

    const FWP_EMPTY: u32 = 0;
    const FWP_UINT16: u32 = 2;
    const FWP_UINT64: u32 = 4;
    // FWP_DATA_TYPE values above 0xff are the address-mask variants from
    // fwptypes.h.  IP_REMOTE_ADDRESS does not accept BYTE_ARRAY16_TYPE for
    // an IPv6 address; it requires FWP_V6_ADDR_MASK and the corresponding
    // FWP_V6_ADDR_AND_MASK layout.
    const FWP_V4_ADDR_MASK: u32 = 0x100;
    const FWP_V6_ADDR_MASK: u32 = 0x101;
    const FWP_MATCH_EQUAL: u32 = 0;
    const FWP_ACTION_BLOCK: u32 = 0x0000_0001;
    const FWP_ACTION_PERMIT: u32 = 0x0000_0002;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    impl Guid {
        const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
            Self {
                data1,
                data2,
                data3,
                data4,
            }
        }

        const fn zero() -> Self {
            Self::new(0, 0, 0, [0; 8])
        }
    }

    #[repr(C)]
    struct DisplayData {
        name: *mut u16,
        description: *mut u16,
    }

    #[repr(C)]
    struct ByteBlob {
        size: u32,
        data: *mut u8,
    }

    #[repr(C)]
    struct Session {
        session_key: Guid,
        display_data: DisplayData,
        flags: u32,
        txn_wait_timeout_in_msec: u32,
        process_id: u32,
        sid: *mut c_void,
        username: *mut u16,
        kernel_mode: i32,
    }

    #[repr(C)]
    struct SubLayer {
        sub_layer_key: Guid,
        display_data: DisplayData,
        flags: u32,
        provider_key: *mut Guid,
        provider_data: ByteBlob,
        weight: u16,
    }

    #[repr(C)]
    union FwpValueData {
        uint16: u16,
        uint64: *mut u64,
    }

    #[repr(C)]
    struct FwpValue {
        type_: u32,
        data: FwpValueData,
    }

    #[repr(C)]
    struct V4AddrAndMask {
        addr: u32,
        mask: u32,
    }

    #[repr(C)]
    struct V6AddrAndMask {
        addr: [u8; 16],
        prefix_length: u8,
    }

    #[repr(C)]
    union FwpConditionData {
        uint16: u16,
        v4_addr_mask: *mut V4AddrAndMask,
        v6_addr_mask: *mut V6AddrAndMask,
    }

    #[repr(C)]
    struct FwpConditionValue {
        type_: u32,
        data: FwpConditionData,
    }

    #[repr(C)]
    struct FilterCondition {
        field_key: Guid,
        match_type: u32,
        condition_value: FwpConditionValue,
    }

    #[repr(C)]
    union ActionData {
        filter_type: Guid,
        callout_key: Guid,
    }

    #[repr(C)]
    struct Action {
        type_: u32,
        data: ActionData,
    }

    #[repr(C)]
    union FilterContext {
        raw_context: u64,
        provider_context_key: Guid,
    }

    #[repr(C)]
    struct Filter {
        filter_key: Guid,
        display_data: DisplayData,
        flags: u32,
        provider_key: *mut Guid,
        provider_data: ByteBlob,
        layer_key: Guid,
        sub_layer_key: Guid,
        weight: FwpValue,
        num_filter_conditions: u32,
        filter_condition: *mut FilterCondition,
        action: Action,
        context: FilterContext,
        reserved: *mut Guid,
        filter_id: u64,
        effective_weight: FwpValue,
    }

    #[link(name = "Fwpuclnt")]
    extern "system" {
        fn FwpmEngineOpen0(
            server_name: *const u16,
            authn_service: u32,
            auth_identity: *const c_void,
            session: *const Session,
            engine_handle: *mut Handle,
        ) -> u32;
        fn FwpmEngineClose0(engine_handle: Handle) -> u32;
        fn FwpmTransactionBegin0(engine_handle: Handle, flags: u32) -> u32;
        fn FwpmTransactionCommit0(engine_handle: Handle) -> u32;
        fn FwpmTransactionAbort0(engine_handle: Handle) -> u32;
        fn FwpmSubLayerAdd0(
            engine_handle: Handle,
            sub_layer: *const SubLayer,
            security_descriptor: *mut c_void,
        ) -> u32;
        fn FwpmSubLayerDeleteByKey0(engine_handle: Handle, key: *const Guid) -> u32;
        fn FwpmFilterAdd0(
            engine_handle: Handle,
            filter: *const Filter,
            security_descriptor: *mut c_void,
            filter_id: *mut u64,
        ) -> u32;
        fn FwpmFilterDeleteById0(engine_handle: Handle, filter_id: u64) -> u32;
    }

    // These are the SDK GUIDs from fwpmu.h. Keeping them here avoids pulling a
    // large Windows bindings crate into the non-Windows/pure-logic build.
    const LAYER_OUTBOUND_TRANSPORT_V4: Guid = Guid::new(
        0x09e61aea,
        0xd214,
        0x46e2,
        [0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8],
    );
    const LAYER_OUTBOUND_TRANSPORT_V6: Guid = Guid::new(
        0xe1735bde,
        0x013f,
        0x4655,
        [0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0],
    );
    const CONDITION_IP_REMOTE_ADDRESS: Guid = Guid::new(
        0xb235ae9a,
        0x1d64,
        0x49b8,
        [0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45],
    );
    const CONDITION_IP_REMOTE_PORT: Guid = Guid::new(
        0xc35a604d,
        0xd22b,
        0x4e1a,
        [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b],
    );
    // A stable private sublayer key makes diagnostics and cleanup predictable.
    const SUBLAYER_KEY: Guid = Guid::new(
        0xa1ce0f46,
        0x0f99,
        0x4d31,
        [0x9a, 0xf4, 0xcf, 0x3e, 0x4f, 0x8d, 0x3e, 0x9b],
    );

    pub struct Guard {
        engine: Handle,
        sub_layer_key: Guid,
        filter_ids: Vec<u64>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            // Explicit deletion makes a normal stop deterministic. The
            // dynamic session is the crash-safety backstop if this code is
            // interrupted before Drop or a filter has already disappeared.
            unsafe {
                for id in self.filter_ids.iter().rev().copied() {
                    let status = FwpmFilterDeleteById0(self.engine, id);
                    if status != ERROR_SUCCESS {
                        log::warn!(
                            "WFP filter cleanup failed for id {id}: Windows error 0x{status:08x}"
                        );
                    }
                }
                let status = FwpmSubLayerDeleteByKey0(self.engine, &self.sub_layer_key);
                if status != ERROR_SUCCESS {
                    log::warn!("WFP sublayer cleanup failed: Windows error 0x{status:08x}");
                }
                let status = FwpmEngineClose0(self.engine);
                if status != ERROR_SUCCESS {
                    log::warn!("WFP engine close failed: Windows error 0x{status:08x}");
                }
            }
        }
    }

    fn win_error(operation: &str, status: u32) -> DpiGuardError {
        DpiGuardError::Driver(format!(
            "WFP {operation} failed with Windows error 0x{status:08x}"
        ))
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn empty_blob() -> ByteBlob {
        ByteBlob {
            size: 0,
            data: ptr::null_mut(),
        }
    }

    fn empty_value() -> FwpValue {
        FwpValue {
            type_: FWP_EMPTY,
            data: FwpValueData {
                uint64: ptr::null_mut(),
            },
        }
    }

    fn port_condition(port: u16) -> FilterCondition {
        FilterCondition {
            field_key: CONDITION_IP_REMOTE_PORT,
            match_type: FWP_MATCH_EQUAL,
            condition_value: FwpConditionValue {
                type_: FWP_UINT16,
                data: FwpConditionData { uint16: port },
            },
        }
    }

    fn v4_address_storage(address: Ipv4Addr) -> V4AddrAndMask {
        V4AddrAndMask {
            // WFP expects the same network-order byte representation returned
            // by inet_addr; `from_ne_bytes` preserves that representation in
            // memory on Windows' little-endian targets.
            addr: u32::from_ne_bytes(address.octets()),
            mask: u32::from_ne_bytes([255, 255, 255, 255]),
        }
    }

    fn v4_address_condition(storage: &mut V4AddrAndMask) -> FilterCondition {
        FilterCondition {
            field_key: CONDITION_IP_REMOTE_ADDRESS,
            match_type: FWP_MATCH_EQUAL,
            condition_value: FwpConditionValue {
                type_: FWP_V4_ADDR_MASK,
                data: FwpConditionData {
                    v4_addr_mask: storage,
                },
            },
        }
    }

    fn v6_address_condition(storage: &mut V6AddrAndMask) -> FilterCondition {
        FilterCondition {
            field_key: CONDITION_IP_REMOTE_ADDRESS,
            match_type: FWP_MATCH_EQUAL,
            condition_value: FwpConditionValue {
                type_: FWP_V6_ADDR_MASK,
                data: FwpConditionData {
                    v6_addr_mask: storage,
                },
            },
        }
    }

    fn add_filter(
        engine: Handle,
        layer: Guid,
        name: &[u16],
        mut conditions: Vec<FilterCondition>,
        action_type: u32,
        weight_number: u64,
    ) -> Result<u64, DpiGuardError> {
        let mut weight_number = weight_number;
        let filter = Filter {
            filter_key: Guid::zero(),
            display_data: DisplayData {
                name: name.as_ptr() as *mut u16,
                description: name.as_ptr() as *mut u16,
            },
            flags: 0,
            provider_key: ptr::null_mut(),
            provider_data: empty_blob(),
            layer_key: layer,
            sub_layer_key: SUBLAYER_KEY,
            weight: FwpValue {
                type_: FWP_UINT64,
                data: FwpValueData {
                    uint64: &mut weight_number,
                },
            },
            num_filter_conditions: conditions.len() as u32,
            filter_condition: conditions.as_mut_ptr(),
            action: Action {
                type_: action_type,
                data: ActionData {
                    filter_type: Guid::zero(),
                },
            },
            context: FilterContext { raw_context: 0 },
            reserved: ptr::null_mut(),
            filter_id: 0,
            effective_weight: empty_value(),
        };
        let mut filter_id = 0u64;
        let status = unsafe { FwpmFilterAdd0(engine, &filter, ptr::null_mut(), &mut filter_id) };
        if status == ERROR_SUCCESS {
            Ok(filter_id)
        } else {
            Err(win_error("FwpmFilterAdd0", status))
        }
    }

    fn abort_and_close(engine: Handle) {
        unsafe {
            let status = FwpmTransactionAbort0(engine);
            if status != ERROR_SUCCESS {
                log::warn!("WFP transaction abort failed: Windows error 0x{status:08x}");
            }
            let status = FwpmEngineClose0(engine);
            if status != ERROR_SUCCESS {
                log::warn!("WFP engine close failed: Windows error 0x{status:08x}");
            }
        }
    }

    pub fn install() -> Result<Guard, DpiGuardError> {
        let session_name = wide("dpi_guard_dns_protect");
        let session_description = wide("dynamic plaintext DNS block; localhost resolver exception");
        let mut session = Session {
            session_key: Guid::zero(),
            display_data: DisplayData {
                name: session_name.as_ptr() as *mut u16,
                description: session_description.as_ptr() as *mut u16,
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txn_wait_timeout_in_msec: 5000,
            process_id: 0,
            sid: ptr::null_mut(),
            username: ptr::null_mut(),
            kernel_mode: 0,
        };
        let mut engine: Handle = ptr::null_mut();
        let status = unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &mut session,
                &mut engine,
            )
        };
        if status != ERROR_SUCCESS || engine.is_null() {
            return Err(win_error("FwpmEngineOpen0", status));
        }

        let status = unsafe { FwpmTransactionBegin0(engine, 0) };
        if status != ERROR_SUCCESS {
            unsafe { FwpmEngineClose0(engine) };
            return Err(win_error("FwpmTransactionBegin0", status));
        }

        let sub_layer_name = wide("dpi_guard DNS protection");
        let sub_layer_description = wide("blocks outbound plaintext DNS except loopback");
        let sub_layer = SubLayer {
            sub_layer_key: SUBLAYER_KEY,
            display_data: DisplayData {
                name: sub_layer_name.as_ptr() as *mut u16,
                description: sub_layer_description.as_ptr() as *mut u16,
            },
            flags: 0,
            provider_key: ptr::null_mut(),
            provider_data: empty_blob(),
            weight: u16::MAX,
        };
        let status = unsafe { FwpmSubLayerAdd0(engine, &sub_layer, ptr::null_mut()) };
        if status != ERROR_SUCCESS {
            abort_and_close(engine);
            return Err(win_error("FwpmSubLayerAdd0", status));
        }

        let mut filter_ids = Vec::with_capacity(4);
        let result = (|| {
            // More-specific permits have a higher filter weight than the
            // catch-all port block, so only 127.0.0.1/::1:53 survives.
            let mut v4_storage = v4_address_storage(Ipv4Addr::LOCALHOST);
            let v4_allow_condition = v4_address_condition(&mut v4_storage);
            let v4_allow = vec![port_condition(53), v4_allow_condition];
            let v4_allow_name = wide("dpi_guard allow loopback DNS v4");
            filter_ids.push(add_filter(
                engine,
                LAYER_OUTBOUND_TRANSPORT_V4,
                &v4_allow_name,
                v4_allow,
                FWP_ACTION_PERMIT,
                2,
            )?);

            let v4_block_name = wide("dpi_guard block plaintext DNS v4");
            filter_ids.push(add_filter(
                engine,
                LAYER_OUTBOUND_TRANSPORT_V4,
                &v4_block_name,
                vec![port_condition(53)],
                FWP_ACTION_BLOCK,
                1,
            )?);

            let mut v6_storage = V6AddrAndMask {
                addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                prefix_length: 128,
            };
            let v6_allow_condition = v6_address_condition(&mut v6_storage);
            let v6_allow = vec![port_condition(53), v6_allow_condition];
            let v6_allow_name = wide("dpi_guard allow loopback DNS v6");
            filter_ids.push(add_filter(
                engine,
                LAYER_OUTBOUND_TRANSPORT_V6,
                &v6_allow_name,
                v6_allow,
                FWP_ACTION_PERMIT,
                2,
            )?);

            let v6_block_name = wide("dpi_guard block plaintext DNS v6");
            filter_ids.push(add_filter(
                engine,
                LAYER_OUTBOUND_TRANSPORT_V6,
                &v6_block_name,
                vec![port_condition(53)],
                FWP_ACTION_BLOCK,
                1,
            )?);
            Ok::<(), DpiGuardError>(())
        })();
        if let Err(error) = result {
            abort_and_close(engine);
            return Err(error);
        }

        let status = unsafe { FwpmTransactionCommit0(engine) };
        if status != ERROR_SUCCESS {
            abort_and_close(engine);
            return Err(win_error("FwpmTransactionCommit0", status));
        }

        Ok(Guard {
            engine,
            sub_layer_key: SUBLAYER_KEY,
            filter_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_is_dynamic_for_crash_safety() {
        assert!(init_wfp_hook_spec().dynamic);
    }

    #[test]
    fn protection_is_two_rules_allow_then_block() {
        let rules = dns_protection_filters();
        assert_eq!(rules.len(), 2);
        assert!(!rules[0].action_block);
        assert_eq!(rules[0].remote_addr, Some(Ipv4Addr::LOCALHOST));
        assert!(rules[1].action_block);
        assert_eq!(rules[1].remote_port, Some(53));
    }

    #[test]
    fn block_port_53_except_localhost_spec_matches_block_rule() {
        let spec = block_port_53_except_localhost_spec();
        assert!(spec.action_block);
        assert_eq!(spec.remote_port, Some(53));
        assert_eq!(spec.layer, "FWPM_LAYER_OUTBOUND_TRANSPORT_V4");
    }

    #[cfg(not(windows))]
    #[test]
    fn block_port_53_requires_windows_wfp() {
        let res = block_port_53_except_localhost();
        assert!(matches!(
            res,
            Err(DpiGuardError::PlatformNotSupported { .. })
        ));
    }

    #[test]
    fn hijack_rejects_loopback_and_unspecified_targets() {
        assert!(hijack_dns_requests_target(Ipv4Addr::LOCALHOST).is_err());
        assert!(hijack_dns_requests_target(Ipv4Addr::UNSPECIFIED).is_err());
        let spec = hijack_dns_requests_spec(Ipv4Addr::new(1, 1, 1, 1)).unwrap();
        assert!(spec.needs_callout_driver);
        let target = hijack_dns_requests_target(Ipv4Addr::new(1, 1, 1, 1)).unwrap();
        assert_eq!(target, Ipv4Addr::new(1, 1, 1, 1));
    }
}
