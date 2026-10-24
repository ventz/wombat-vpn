import Foundation
import Testing
@testable import TunnelCore

/// `wombat completion install` refuses a development build: its links would dangle after a clean.
@Suite struct BuildLocationTests {
    @Test func xcodeBuildFoldersAreDevelopmentBuilds() {
        let completions = "Contents/Resources/completions/_wombat"
        #expect(BuildLocation.isDevelopmentBuild("/Users/v/Library/Developer/Xcode/DerivedData/Wombat-abc/Build/Products/Release/Wombat.app/\(completions)"))
        #expect(BuildLocation.isDevelopmentBuild("/Users/v/git/wombat-vpn/build.noindex/DerivedData/Build/Products/Debug/Wombat Debug.app/\(completions)"))
        #expect(BuildLocation.isDevelopmentBuild("/tmp/out/Build/Products/Release/Wombat.app/\(completions)"))  // -derivedDataPath /tmp/out
        #expect(BuildLocation.isDevelopmentBuild("/Users/v/derivedDATA/x/Wombat.app/\(completions)"))  // case-insensitive volume
        #expect(BuildLocation.isDevelopmentBuild("/Users/v/DerivedDataRelease/Build/Intermediates.noindex/ArchiveIntermediates/Wombat/InstallationBuildProductsLocation/Applications/Wombat.app/\(completions)"))
        #expect(BuildLocation.isDevelopmentBuild("/Users/v/git/wombat-vpn/build.noindex/signed/Wombat.xcarchive/Products/Applications/Wombat.app/\(completions)"))
        #expect(BuildLocation.isDevelopmentBuild("/Users/v/git/wombat-vpn/build.noindex/signed/export/Wombat.app/\(completions)"))  // build-signed.sh
    }

    @Test func installedAppsAreNot() {
        let completions = "Contents/Resources/completions/_wombat"
        #expect(!BuildLocation.isDevelopmentBuild("/Applications/Wombat.app/\(completions)"))
        #expect(!BuildLocation.isDevelopmentBuild("/Users/v/Applications/Wombat.app/\(completions)"))  // brew --appdir=~/Applications
        #expect(!BuildLocation.isDevelopmentBuild("/Applications/Utilities/Wombat.app/\(completions)"))
        // Folders merely named Build or Products, or names that only contain the words.
        #expect(!BuildLocation.isDevelopmentBuild("/Users/v/Build/Products/Wombat.app/\(completions)"))
        #expect(!BuildLocation.isDevelopmentBuild("/Users/v/MyBuild/Products/Release/Wombat.app/\(completions)"))
        #expect(!BuildLocation.isDevelopmentBuild("/Users/v/Build/Products/Release/NotAnApp/Wombat.app/\(completions)"))
        #expect(!BuildLocation.isDevelopmentBuild(""))
        #expect(!BuildLocation.isDevelopmentBuild("/"))
    }
}
