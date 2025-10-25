package com.kuru.raspeval.tests.examples

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import com.kuru.raspeval.core.ManagedTestCase
import com.kuru.raspeval.core.Priority
import com.kuru.raspeval.core.TestLayer
import com.kuru.raspeval.core.TestRequirement
import com.kuru.raspeval.core.TestResult
import java.security.MessageDigest

class Test_6_AppTamperRepackage : ManagedTestCase() {
    override val requirement = TestRequirement("6", "Group 1", "App Tamper/Repackage", Priority.P2, TestLayer.MANAGED)
    override suspend fun execute(context: Context): TestResult {
        return try {
            val packageName = context.packageName
            val packageManager = context.packageManager

            @Suppress("DEPRECATION")
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo.apkContentsSigners
            } else {
                packageInfo.signatures
            }

            if (signatures.isNullOrEmpty()) {
                return TestResult.Fail("Could not retrieve app signature.", "Signature list is null or empty.")
            }

            // For simplicity, we check the first signature. A robust implementation would check all of them.
            val signatureBytes = signatures[0].toByteArray()
            val messageDigest = MessageDigest.getInstance("SHA-256")
            val digest = messageDigest.digest(signatureBytes)
            val currentSignatureHash = Base64.encodeToString(digest, Base64.NO_WRAP)

            // NOTE: Replace this with your actual release signature hash.
            // You should not store this directly in the code in a real app.
            // Consider fetching it from a secure server or using obfuscation.
            val expectedSignatureHash = "YOUR_RELEASE_SIGNATURE_SHA256_HASH"

            if (currentSignatureHash == expectedSignatureHash) {
                TestResult.Pass("App signature is valid.")
            } else {
                TestResult.Fail(
                    reason = "App signature mismatch. The app may have been tampered with or repackaged.",
                    details = "Expected hash: $expectedSignatureHash, but got: $currentSignatureHash"
                )
            }
        } catch (e: Exception) {
            TestResult.Error(e)
        }
    }
}