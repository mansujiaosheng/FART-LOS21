package com.fartlos21.helper;

// Bridge class with native method for active invoke.
// The Runnable is an inner class for simplicity.
public class FartBridge {
    // Called from Java thread (no AttachCurrentThread needed)
    public static native void nativeActiveInvoke();

    // Runnable that triggers nativeActiveInvoke
    public static class InvokeRunnable implements Runnable {
        @Override
        public void run() {
            nativeActiveInvoke();
        }
    }
}
