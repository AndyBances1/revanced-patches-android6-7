package app.revanced.patches.youtube.layout.general.pivotbar.createbutton.bytecode.patch

import app.revanced.patcher.annotation.Name
import app.revanced.patcher.annotation.Version
import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.PatchResult
import app.revanced.patcher.patch.PatchResultError
import app.revanced.patcher.patch.PatchResultSuccess
import app.revanced.patcher.patch.annotations.DependsOn
import app.revanced.patches.youtube.layout.general.pivotbar.createbutton.bytecode.fingerprints.*
import app.revanced.patches.youtube.misc.resourceid.patch.SharedResourcdIdPatch
import app.revanced.shared.annotation.YouTubeCompatibility
import app.revanced.shared.extensions.toErrorResult
import app.revanced.shared.util.integrations.Constants.GENERAL_LAYOUT
import app.revanced.shared.util.pivotbar.InjectionUtils.REGISTER_TEMPLATE_REPLACEMENT
import app.revanced.shared.util.pivotbar.InjectionUtils.injectHook
import org.jf.dexlib2.dexbacked.reference.DexBackedMethodReference
import org.jf.dexlib2.iface.instruction.ReferenceInstruction

@Name("hide-create-button-bytecode-patch")
@DependsOn([SharedResourcdIdPatch::class])
@YouTubeCompatibility
@Version("0.0.1")
class CreateButtonRemoverBytecodePatch : BytecodePatch(
    listOf(
        PivotBarCreateButtonViewFingerprint,
        PivotBarFingerprint
    )
) {
    override fun execute(context: BytecodeContext): PatchResult {

        /*
         * Resolve fingerprints
         */

        PivotBarFingerprint.result?.let {
            val startIndex = it.scanResult.patternScanResult!!.startIndex
            val pivotBarInstructions = it.mutableMethod.implementation!!.instructions
            createRef = (pivotBarInstructions.elementAt(startIndex) as ReferenceInstruction).reference as DexBackedMethodReference
        } ?: return PivotBarFingerprint.toErrorResult()

        PivotBarCreateButtonViewFingerprint.result?.let {
            with (it.mutableMethod){
                val createButtonInstructions = implementation!!.instructions
                createButtonInstructions.filter { instruction ->
                    val fieldReference = (instruction as? ReferenceInstruction)?.reference as? DexBackedMethodReference
                    fieldReference?.let { it.definingClass == createRef.definingClass && it.name == createRef.name } == true
                }.forEach { instruction ->
                    if (!isSeondary) {
                        isSeondary = true;
                        return@forEach
                    }

                    /*
                    * Inject hooks
                    */

                    injectHook(hook, createButtonInstructions.indexOf(instruction) + 2)

                    return PatchResultSuccess()
                }
                return PatchResultError("Could not find the method to hook.")
            }
        } ?: return PivotBarCreateButtonViewFingerprint.toErrorResult()
    }

    internal companion object {
        const val hook =
            "invoke-static { v$REGISTER_TEMPLATE_REPLACEMENT }, $GENERAL_LAYOUT" +
            "->" +
            "hideCreateButton(Landroid/view/View;)V"

        private lateinit var createRef: DexBackedMethodReference

        private var isSeondary: Boolean = false
    }
}
