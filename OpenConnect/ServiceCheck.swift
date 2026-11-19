import Foundation

/// Whether launchd knows this extension's own XPC service. When macOS replaces the extension
/// while the old process is still exiting, the new launchd job is created without it ("The
/// endpoint ... already exists and is owned by" the old job; then "failed activation ...
/// Operation not permitted" at every launch, 2026-11-18). The app then can't reach this
/// process until the Mac restarts or a newer build replaces the extension (`ExtensionService`);
/// `ProviderHandOff` is the way around it for connects meanwhile.
enum ServiceCheck {
    /// true only for launchd's definite "unknown service"; any other failure (a sandbox refusal,
    /// say) is not taken as proof.
    static func ownServiceMissing() -> Bool {
        #if WOMBAT_TEST_BACKUP_HANDOFF
        return true  // test builds only (scripts/build-signed.sh): prove the backup route
        #else
        return MachServiceLookup.state(of: AppIdentity.openConnectMachService) == .missing
        #endif
    }
}
