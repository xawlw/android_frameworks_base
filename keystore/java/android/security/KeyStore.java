/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.security;

import android.compat.annotation.UnsupportedAppUsage;
import android.os.Build;
import android.os.UserHandle;
import android.security.maintenance.UserState;
import android.system.keystore2.Domain;

/**
 * @hide This should not be made public in its present form because it
 * assumes that private and secret key bytes are available and would
 * preclude the use of hardware crypto.
 */
public class KeyStore {
    private static final String TAG = "KeyStore";

    // ResponseCodes - see system/security/keystore/include/keystore/keystore.h
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    public static final int NO_ERROR = 1;

    // Used for UID field to indicate the calling UID.
    public static final int UID_SELF = -1;

    // States
    public enum State {
        @UnsupportedAppUsage
        UNLOCKED,
        @UnsupportedAppUsage
        LOCKED,
        UNINITIALIZED
    };

    private static final KeyStore KEY_STORE = new KeyStore();

    @UnsupportedAppUsage
    public static KeyStore getInstance() {
        return KEY_STORE;
    }

    /** @hide */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    public State state(int userId) {
        int userState = AndroidKeyStoreMaintenance.getState(userId);
        switch (userState) {
            case UserState.UNINITIALIZED:
                return KeyStore.State.UNINITIALIZED;
            case UserState.LSKF_UNLOCKED:
                return KeyStore.State.UNLOCKED;
            case UserState.LSKF_LOCKED:
                return KeyStore.State.LOCKED;
            default:
                throw new AssertionError(userState);
        }
    }

    /** @hide */
    @UnsupportedAppUsage
    public State state() {
        return state(UserHandle.myUserId());
    }

    /** @hide */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    public byte[] get(String key) {
        return null;
    }

    /** @hide */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    public boolean delete(String key) {
        return false;
    }

    /**
     * List uids of all keys that are auth bound to the current user.
     * Only system is allowed to call this method.
     * @hide
     * @deprecated This function always returns null.
     */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    public int[] listUidsOfAuthBoundKeys() {
        return null;
    }


    /**
     * @hide
     * @deprecated This function has no effect.
     */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    public boolean unlock(String password) {
        return false;
    }

    /**
     *
     * @return
     * @deprecated This function always returns true.
     * @hide
     */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    public boolean isEmpty() {
        return true;
    }

    /**
     * Forwards the request to clear a UID to Keystore 2.0.
     * @hide
     */
    public boolean clearUid(int uid) {
        return AndroidKeyStoreMaintenance.clearNamespace(Domain.APP, uid) == 0;
    }


    /**
     * Add an authentication record to the keystore authorization table.
     *
     * @param authToken The packed bytes of a hw_auth_token_t to be provided to keymaster.
     * @return {@code KeyStore.NO_ERROR} on success, otherwise an error value corresponding to
     * a {@code KeymasterDefs.KM_ERROR_} value or {@code KeyStore} ResponseCode.
     */
    public int addAuthToken(byte[] authToken) {
<<<<<<< HEAD
        try {
            return mBinder.addAuthToken(authToken);
        } catch (RemoteException e) {
            Log.w(TAG, "Cannot connect to keystore", e);
            return SYSTEM_ERROR;
        }
    }

    /**
     * Notify keystore that a user's password has changed.
     *
     * @param userId the user whose password changed.
     * @param newPassword the new password or "" if the password was removed.
     */
    public boolean onUserPasswordChanged(int userId, String newPassword) {
        // Parcel.cpp doesn't support deserializing null strings and treats them as "". Make that
        // explicit here.
        if (newPassword == null) {
            newPassword = "";
        }
        try {
            return mBinder.onUserPasswordChanged(userId, newPassword) == NO_ERROR;
        } catch (RemoteException e) {
            Log.w(TAG, "Cannot connect to keystore", e);
            return false;
        }
    }

    /**
     * Notify keystore that a user was added.
     *
     * @param userId the new user.
     * @param parentId the parent of the new user, or -1 if the user has no parent. If parentId is
     * specified then the new user's keystore will be intialized with the same secure lockscreen
     * password as the parent.
     */
    public void onUserAdded(int userId, int parentId) {
        try {
            mBinder.onUserAdded(userId, parentId);
        } catch (RemoteException e) {
            Log.w(TAG, "Cannot connect to keystore", e);
        }
    }

    /**
     * Notify keystore that a user was added.
     *
     * @param userId the new user.
     */
    public void onUserAdded(int userId) {
        onUserAdded(userId, -1);
    }

    /**
     * Notify keystore that a user was removed.
     *
     * @param userId the removed user.
     */
    public void onUserRemoved(int userId) {
        try {
            mBinder.onUserRemoved(userId);
        } catch (RemoteException e) {
            Log.w(TAG, "Cannot connect to keystore", e);
        }
    }

    public boolean onUserPasswordChanged(String newPassword) {
        return onUserPasswordChanged(UserHandle.getUserId(Process.myUid()), newPassword);
    }

    /**
     * Notify keystore about the latest user locked state. This is to support keyguard-bound key.
     */
    public void onUserLockedStateChanged(int userHandle, boolean locked) {
        try {
            mBinder.onKeyguardVisibilityChanged(locked, userHandle);
        } catch (RemoteException e) {
            Log.w(TAG, "Failed to update user locked state " + userHandle, e);
        }
    }

    private class KeyAttestationCallbackResult {
        private KeystoreResponse keystoreResponse;
        private KeymasterCertificateChain certificateChain;

        public KeyAttestationCallbackResult(KeystoreResponse keystoreResponse,
                KeymasterCertificateChain certificateChain) {
            this.keystoreResponse = keystoreResponse;
            this.certificateChain = certificateChain;
        }

        public KeystoreResponse getKeystoreResponse() {
            return keystoreResponse;
        }

        public void setKeystoreResponse(KeystoreResponse keystoreResponse) {
            this.keystoreResponse = keystoreResponse;
        }

        public KeymasterCertificateChain getCertificateChain() {
            return certificateChain;
        }

        public void setCertificateChain(KeymasterCertificateChain certificateChain) {
            this.certificateChain = certificateChain;
        }
    }

    private class CertificateChainPromise
            extends android.security.keystore.IKeystoreCertificateChainCallback.Stub
            implements IBinder.DeathRecipient {
        final private CompletableFuture<KeyAttestationCallbackResult> future = new CompletableFuture<KeyAttestationCallbackResult>();
        @Override
        public void onFinished(KeystoreResponse keystoreResponse,
                KeymasterCertificateChain certificateChain) throws android.os.RemoteException {
            future.complete(new KeyAttestationCallbackResult(keystoreResponse, certificateChain));
        }
        public final CompletableFuture<KeyAttestationCallbackResult> getFuture() {
            return future;
        }
        @Override
        public void binderDied() {
            future.completeExceptionally(new RemoteException("Keystore died"));
        }
    };


    public int attestKey(
            String alias, KeymasterArguments params, KeymasterCertificateChain outChain) {
        // Prevent Google Play Services from using key attestation for SafetyNet
        if (mContext.getPackageName().equals("com.google.android.gms")) {
            return KeymasterDefs.KM_ERROR_KEY_RATE_LIMIT_EXCEEDED;
        }

        CertificateChainPromise promise = new CertificateChainPromise();
        try {
            mBinder.asBinder().linkToDeath(promise, 0);
            if (params == null) {
                params = new KeymasterArguments();
            }
            if (outChain == null) {
                outChain = new KeymasterCertificateChain();
            }
            int error = mBinder.attestKey(promise, alias, params);
            if (error != NO_ERROR) return error;
            KeyAttestationCallbackResult result = interruptedPreservingGet(promise.getFuture());
            error = result.getKeystoreResponse().getErrorCode();
            if (error == NO_ERROR) {
                outChain.shallowCopyFrom(result.getCertificateChain());
            }
            return error;
        } catch (RemoteException e) {
            Log.w(TAG, "Cannot connect to keystore", e);
            return SYSTEM_ERROR;
        } catch (ExecutionException e) {
            Log.e(TAG, "AttestKey completed with exception", e);
            return SYSTEM_ERROR;
        } finally {
            mBinder.asBinder().unlinkToDeath(promise, 0);
        }
    }

    public int attestDeviceIds(KeymasterArguments params, KeymasterCertificateChain outChain) {
        CertificateChainPromise promise = new CertificateChainPromise();
        try {
            mBinder.asBinder().linkToDeath(promise, 0);
            if (params == null) {
                params = new KeymasterArguments();
            }
            if (outChain == null) {
                outChain = new KeymasterCertificateChain();
            }
            int error = mBinder.attestDeviceIds(promise, params);
            if (error != NO_ERROR) return error;
            KeyAttestationCallbackResult result = interruptedPreservingGet(promise.getFuture());
            error = result.getKeystoreResponse().getErrorCode();
            if (error == NO_ERROR) {
                outChain.shallowCopyFrom(result.getCertificateChain());
            }
            return error;
        } catch (RemoteException e) {
            Log.w(TAG, "Cannot connect to keystore", e);
            return SYSTEM_ERROR;
        } catch (ExecutionException e) {
            Log.e(TAG, "AttestDevicdeIds completed with exception", e);
            return SYSTEM_ERROR;
        } finally {
            mBinder.asBinder().unlinkToDeath(promise, 0);
        }
=======
        return Authorization.addAuthToken(authToken);
>>>>>>> 1a7b0835ced351de3f8f73b29a3b40996d335e65
    }

    /**
     * Notify keystore that the device went off-body.
     */
    public void onDeviceOffBody() {
        AndroidKeyStoreMaintenance.onDeviceOffBody();
    }

    /**
     * Returns a {@link KeyStoreException} corresponding to the provided keystore/keymaster error
     * code.
     */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    public static KeyStoreException getKeyStoreException(int errorCode) {
        return new KeyStoreException(-10000, "Should not be called.");
    }
}
