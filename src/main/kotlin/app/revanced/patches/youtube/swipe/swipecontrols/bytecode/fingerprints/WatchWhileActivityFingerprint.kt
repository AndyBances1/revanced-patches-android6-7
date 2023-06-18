package app.revanced.patches.youtube.swipe.swipecontrols.bytecode.fingerprints

import app.revanced.patcher.fingerprint.method.impl.MethodFingerprint

object WatchWhileActivityFingerprint : MethodFingerprint(
    customFingerprint = { methodDef, _ ->
        methodDef.definingClass.endsWith("WatchWhileActivity;")
                && methodDef.name == "<init>"
    }
)
