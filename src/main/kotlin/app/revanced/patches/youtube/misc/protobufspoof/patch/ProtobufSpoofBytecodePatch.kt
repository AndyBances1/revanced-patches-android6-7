package app.revanced.patches.youtube.misc.protobufspoof.patch

import app.revanced.patcher.annotation.Name
import app.revanced.patcher.annotation.Version
import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.data.toMethodWalker
import app.revanced.patcher.extensions.InstructionExtensions.addInstruction
import app.revanced.patcher.extensions.InstructionExtensions.addInstructions
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.PatchResult
import app.revanced.patcher.patch.PatchResultSuccess
import app.revanced.patcher.patch.annotations.DependsOn
import app.revanced.patcher.util.proxy.mutableTypes.MutableMethod
import app.revanced.patches.youtube.misc.playertype.patch.PlayerTypeHookPatch
import app.revanced.patches.youtube.misc.protobufpoof.fingerprints.ProtobufParameterBuilderFingerprint
import app.revanced.patches.youtube.misc.protobufspoof.fingerprints.BadResponseFingerprint
import app.revanced.patches.youtube.misc.protobufspoof.fingerprints.SubtitleWindowFingerprint
import app.revanced.shared.annotation.YouTubeCompatibility
import app.revanced.shared.extensions.toErrorResult
import app.revanced.shared.util.integrations.Constants.MISC_PATH

/*
* from 2.168.3
* https://github.com/inotia00/revanced-patches/commit/c55f07728a4d9842654c69a11702b0a09c5cc3e4
*/
@Name("protobuf-spoof-bytecode-patch")
@DependsOn([PlayerTypeHookPatch::class])
@YouTubeCompatibility
@Version("0.0.1")
class ProtobufSpoofBytecodePatch : BytecodePatch(
    listOf(
        BadResponseFingerprint,
        ProtobufParameterBuilderFingerprint,
        SubtitleWindowFingerprint
    )
) {
    override fun execute(context: BytecodeContext): PatchResult {

        // hook parameter
        ProtobufParameterBuilderFingerprint.result?.let {
            with (context
                .toMethodWalker(it.method)
                .nextMethod(it.scanResult.patternScanResult!!.startIndex, true)
                .getMethod() as MutableMethod
            ) {
                val protobufParam = 3

                addInstructions(
                    0,
                    """
                        invoke-static {p$protobufParam}, $MISC_PATH/ProtobufSpoofPatch;->overrideProtobufParameter(Ljava/lang/String;)Ljava/lang/String;
                        move-result-object p$protobufParam
                    """
                )
            }
        } ?: return ProtobufParameterBuilderFingerprint.toErrorResult()

        // hook video playback result
        BadResponseFingerprint.result?.mutableMethod?.addInstruction(
            0,
            "invoke-static {}, $MISC_PATH/ProtobufSpoofPatch;->switchProtobufSpoof()V"
        ) ?: return BadResponseFingerprint.toErrorResult()

        // fix protobuf spoof side issue
        SubtitleWindowFingerprint.result?.mutableMethod?.addInstructions(
            0,
            """
                invoke-static {p1, p2, p3, p4, p5}, $MISC_PATH/ProtobufSpoofPatch;->getSubtitleWindowSettingsOverride(IIIZZ)[I
                move-result-object v0
                const/4 v1, 0x0
                aget p1, v0, v1     # ap, anchor configuration
                const/4 v1, 0x1
                aget p2, v0, v1     # ah, horizontal anchor
                const/4 v1, 0x2
                aget p3, v0, v1     # av, vertical anchor
            """
        ) ?: return SubtitleWindowFingerprint.toErrorResult()

        return PatchResultSuccess()
    }
}