/*
 * Copyright (C) 2013 The Android Open Source Project
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
package com.example.android.cardreader;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.MifareClassic;

import com.example.android.common.logger.Log;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.Arrays;

/**
 * Callback class, invoked when an NFC card is scanned while the device is running in reader mode.
 *
 * Reader mode can be invoked by calling NfcAdapter
 */
public class LoyaltyCardReader implements NfcAdapter.ReaderCallback {
    private static final String TAG = "LoyaltyCardReader";
    // AID for our loyalty card service.
    private static final String SAMPLE_LOYALTY_CARD_AID = "F222222222";
    //Adding some default keys

    private static final byte[][] DEFAULT_KEYS = {
            {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF},
            {(byte)0xa0, (byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0xa4, (byte)0xa5},
            {(byte)0xd3, (byte)0xf7, (byte)0xd3, (byte)0xf7, (byte)0xd3, (byte)0xf7},
            {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00},
            {(byte)0xb0, (byte)0xb1, (byte)0xb2, (byte)0xb3, (byte)0xb4, (byte)0xb5},
            {(byte)0x4d, (byte)0x3a, (byte)0x99, (byte)0xc3, (byte)0x51, (byte)0xdd},
            {(byte)0x1a, (byte)0x98, (byte)0x2c, (byte)0x7e, (byte)0x45, (byte)0x9a},
            {(byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff},
            {(byte)0x71, (byte)0x4c, (byte)0x5c, (byte)0x88, (byte)0x6e, (byte)0x97},
            {(byte)0x58, (byte)0x7e, (byte)0xe5, (byte)0xf9, (byte)0x35, (byte)0x0f},
            {(byte)0xa0, (byte)0x47, (byte)0x8c, (byte)0xc3, (byte)0x90, (byte)0x91},
            {(byte)0x53, (byte)0x3c, (byte)0xb6, (byte)0xc7, (byte)0x23, (byte)0xf6},
            {(byte)0x8f, (byte)0xd0, (byte)0xa4, (byte)0xf2, (byte)0x56, (byte)0xe9}
    };

    // ISO-DEP command HEADER for selecting an AID.
    // Format: [Class | Instruction | Parameter 1 | Parameter 2]
    private static final String SELECT_APDU_HEADER = "00A40400";
    // "OK" status word sent in response to SELECT AID command (0x9000)
    private static final byte[] SELECT_OK_SW = {(byte) 0x90, (byte) 0x00};

    // Weak reference to prevent retain loop. mAccountCallback is responsible for exiting
    // foreground mode before it becomes invalid (e.g. during onPause() or onStop()).
    private WeakReference<AccountCallback> mAccountCallback;

    public interface AccountCallback {
        public void onAccountReceived(String account);
    }

    public LoyaltyCardReader(AccountCallback accountCallback) {
        mAccountCallback = new WeakReference<AccountCallback>(accountCallback);
    }

    /**
     * Callback when a new tag is discovered by the system.
     *
     * <p>Communication with the card should take place here.
     *
     * @param tag Discovered tag
     */
    @Override
    public void onTagDiscovered(Tag tag) {
        Log.i(TAG, "New tag discovered");
        String metaInfo = "";
        // Android's Host-based Card Emulation (HCE) feature implements the ISO-DEP (ISO 14443-4)
        // protocol.
        //
        // In order to communicate with a device using HCE, the discovered tag should be processed
        // using the MIFARE Classic EV1 class.
        MifareClassic mifare = MifareClassic.get(tag);
        if (mifare != null) {
            try {
                // Connect to the remote NFC device
                mifare.connect();
                // Build SELECT AID command for our loyalty card service.
                // This command tells the remote device which service we wish to communicate with.
                int secCount = mifare.getSectorCount();
                int bCount = 0;
                int bIndex = 0;
                boolean auth = false;
                byte[] data;

                for(int j = 0; j < secCount; j++) {
                    // 6.1) authenticate the sector
                    for (int ind = 0; ind < DEFAULT_KEYS.length; ind++){
                        auth = mifare.authenticateSectorWithKeyA(j, DEFAULT_KEYS[ind]);
                        if (auth) {
                            // 6.2) In each sector - get the block count
                            bCount = mifare.getBlockCountInSector(j);
                            bIndex = mifare.sectorToBlock(j);
                            for (int i = 0; i < bCount; i++) {
                                // 6.3) Read the block
                                data = mifare.readBlock(bIndex);
                                // 7) Convert the data into a string from Hex format.
                                Log.i(TAG, "Sector:" + j + " Block:" + bIndex + " Key:" + ByteArrayToHexString(DEFAULT_KEYS[ind]) + "\n");
                                String str_data = new String(data, "UTF-8");
                                Log.i(TAG, "Data:" + str_data + "\n");
                                bIndex++;
                            }
                        }
                    }
                }
            } catch (IOException e) {
                Log.e(TAG, "Error communicating with card: " + e.toString());
            }
        }
    }

    /**
     * Build APDU for SELECT AID command. This command indicates which service a reader is
     * interested in communicating with. See ISO 7816-4.
     *
     * @param aid Application ID (AID) to select
     * @return APDU for SELECT AID command
     */
    public static byte[] BuildSelectApdu(String aid) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
        return HexStringToByteArray(SELECT_APDU_HEADER + String.format("%02X", aid.length() / 2) + aid);
    }

    /**
     * Utility class to convert a byte array to a hexadecimal string.
     *
     * @param bytes Bytes to convert
     * @return String, containing hexadecimal representation.
     */
    public static String ByteArrayToHexString(byte[] bytes) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for ( int j = 0; j < bytes.length; j++ ) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Utility class to convert a hexadecimal string to a byte string.
     *
     * <p>Behavior with input strings containing non-hexadecimal characters is undefined.
     *
     * @param s String containing hexadecimal characters to convert
     * @return Byte array generated from input
     */
    public static byte[] HexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

}
