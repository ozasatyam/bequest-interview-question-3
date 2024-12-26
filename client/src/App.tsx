import React, { useEffect, useState } from "react";
import LZString from "lz-string";
import { db } from "./db";
import CryptoJS from "crypto-js";


function App() {
  const [data, setData] = useState<string>("");
  const [signature, setSignature] = useState<string>("");
  const [verified, setVerified] = useState<boolean | null>(null);
  const [versionHistory, setVersionHistory] = useState<
    { data: string; signature: string; timestamp: number }[]
  >([]);


  useEffect(() => {

    sendPublicKey();
  }, []);
  useEffect(() => {
    const savedHistory = localStorage.getItem('versionHistory');
    if (savedHistory) {
      const decompressed = LZString.decompress(savedHistory);
      console.log(decompressed, "decompressed")
      const history = JSON.parse(decompressed);
      // Decrypt each version's data
      const decryptedHistory = history.map((version: any) => ({
        ...version,
        data: decryptData(version.data)
      }));
      setVersionHistory(decryptedHistory);
    }
  }, []);
  const handleRecoveryData = async (lastValidVersion: { data: string; signature: string }) => {
    try {
      // Verify the signature of the recovery version
      const decryptedData = lastValidVersion.data

      const isValid = await verifyData(decryptedData, lastValidVersion.signature);

      if (isValid) {
        // Restore the last valid version
        setData(decryptedData);
        setSignature(lastValidVersion.signature);
        alert('Data recovered to last valid version');
      } else {
        alert('Warning: Recovery version signature is invalid!');
      }
    } catch (error) {
      console.error('Error recovering data:', error);
      alert('Failed to recover data');
    }
  };
  const sendToBackend = async (signature: string): Promise<void> => {
    try {
      // const clientId = localStorage.getItem('clientId');
      const response = await fetch('http://localhost:8080/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          data,
          signature
        }),
      });


      const result = await response.json();
      if (result.error) {
        setVerified(false);
        // Handle recovery data if needed
        if (result.lastValidVersion) {
          // Option to recover last valid version
          handleRecoveryData(result.lastValidVersion);
        }
      } else {
        setVerified(true);
      }
    } catch (error) {
      console.error('Error:', error);
      setVerified(false);
    }
  };
  const sendPublicKey = async () => {
    try {
      const { publicKey } = await initializeKeys()

      await fetch('http://localhost:8080/register-key', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ publicKey }),
      });
    } catch (error) {
      console.error('Error sending public key:', error);
    }
  };
  const initializeKeys = async (): Promise<{ publicKey: string; privateKey: string }> => {
    if (!localStorage.getItem("publicKey") || !localStorage.getItem("privateKey")) {
      const { publicKey, privateKey } = await generateKeyPair();
      localStorage.setItem("publicKey", publicKey);
      localStorage.setItem("privateKey", privateKey);
      return { publicKey, privateKey }
    }
    return {
      publicKey: localStorage.getItem("publicKey") || "",
      privateKey: localStorage.getItem("privateKey") || "",
    };
  };

  const generateKeyPair = async (): Promise<{ publicKey: string; privateKey: string }> => {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: { name: "SHA-256" },
      },
      true,
      ["sign", "verify"]
    );

    const publicKey = await exportKey(keyPair.publicKey);
    const privateKey = await exportKey(keyPair.privateKey);

    return { publicKey, privateKey };
  };

  const exportKey = async (key: CryptoKey): Promise<string> => {
    const exported = await window.crypto.subtle.exportKey(
      key.type === "public" ? "spki" : "pkcs8",
      key
    );
    const base64 = bufferToBase64(exported);
    const type = key.type === "public" ? "PUBLIC KEY" : "PRIVATE KEY";
    return `-----BEGIN ${type}-----\n${base64.match(/.{1,64}/g)?.join("\n")}\n-----END ${type}-----`;
  };

  const bufferToBase64 = (buffer: ArrayBuffer): string =>
    btoa(String.fromCharCode(...new Uint8Array(buffer)));

  const base64ToBuffer = (base64: string): ArrayBuffer =>
    Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;

  const signData = async (data: string): Promise<string> => {
    const privateKey = await importPrivateKey(localStorage.getItem("privateKey") || "");
    const encodedData = new TextEncoder().encode(data);
    console.log(encodedData, "encodedData", privateKey)
    const signature = await window.crypto.subtle.sign(
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      privateKey,
      encodedData
    );

    return bufferToBase64(signature);
  };

  const verifyData = async (dataToVerify: string, signatureToVerify: string): Promise<boolean> => {
    try {
      const publicKey = await importPublicKey(localStorage.getItem("publicKey") || "");
      const encodedData = new TextEncoder().encode(dataToVerify);
      console.log(encodedData, "encodedData", publicKey, signatureToVerify)
      const isValid = await window.crypto.subtle.verify(
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: { name: "SHA-256" },
        },
        publicKey,
        base64ToBuffer(signatureToVerify),
        encodedData
      );

      setVerified(isValid);
      return isValid;
    } catch (error) {
      console.error('Verification error:', error);
      setVerified(false);
      return false;
    }
  };

  const importPrivateKey = async (pem: string): Promise<CryptoKey> => {
    console.log(pem, "pem")
    const binaryDer = base64ToBuffer(pemToBase64(pem));
    console.log(binaryDer, "binaryDer")
    const privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      binaryDer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      true,
      ["sign"]
    )
    console.log(privateKey, "privateKey")
    // return privateKey
    return privateKey;
  };

  const importPublicKey = async (pem: string): Promise<CryptoKey> => {
    const binaryDer = base64ToBuffer(pemToBase64(pem));
    return await window.crypto.subtle.importKey(
      "spki",
      binaryDer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      true,
      ["verify"]
    );
  };

  const pemToBase64 = (pem: string): string => {
    // Remove headers, footers, and newlines
    return pem
      .replace(/-----BEGIN.*?-----/, '')
      .replace(/-----END.*?-----/, '')
      .replace(/[\n\r]/g, '');
  };
  const encryptData = (data: string): string => {
    const password = localStorage.getItem('dataPassword');
    return CryptoJS.AES.encrypt(data, password || 'default-key').toString();
  };

  const decryptData = (encrypted: string): string => {
    const password = localStorage.getItem('dataPassword');
    const bytes = CryptoJS.AES.decrypt(encrypted, password || 'default-key');
    return bytes.toString(CryptoJS.enc.Utf8);
  };
  const updateData = async (): Promise<void> => {
    // try {
    console.log("newSignature")

    const newSignature = await signData(data);
    console.log(newSignature, "newSignature")
    setSignature(newSignature);

    const newVersion = {
      data: data,
      signature: newSignature,
      timestamp: Date.now()
    };

    setVersionHistory(prev => {
      const updated = [...prev, newVersion];
      console.log(updated, "updated")
      const compressed = LZString.compress(JSON.stringify([...prev,{ ...newVersion,data: encryptData(data)}]));
      console.log(compressed, "compressed")
      localStorage.setItem('versionHistory', compressed);
      return updated;
    });

    await sendToBackend(newSignature);
    // } catch (error) {
    //   console.error('Error updating data:', error);
    // }
  };

  // Add recovery function
  const recoverData = async (version: { data: string; signature: string }) => {
    try {
      // Verify the signature of the selected version
      const isValid = await verifyData(version.data, version.signature);
      if (!isValid) {
        alert('Warning: This version\'s signature is invalid!');
        return;
      }

      setData(version.data);
      setSignature(version.signature);
    } catch (error) {
      console.error('Error recovering data:', error);
    }
  };

  const backupData = async () => {
    const backup = {
      versionHistory,
      lastBackup: Date.now()
    };

    // Save to IndexedDB
    await db.backups.add(backup);

    // Save to alternative storage (e.g., WebStorage)
    localStorage.setItem('backup', JSON.stringify(backup));
  };

  return (
    <div style={{ padding: 20 }}>
      <h1>Tamper-Proof Data</h1>
      <textarea
        rows={5}
        cols={40}
        value={data}
        onChange={(e) => setData(e.target.value)}
      />
      <br />
      <button onClick={updateData}>Sign & Save Data</button>
      <button onClick={() => verifyData(data, signature)}>Verify Current Data</button>

      {verified !== null && (
        <p style={{ color: verified ? 'green' : 'red' }}>
          Data is {verified ? "Valid" : "Tampered"}
        </p>
      )}

      <h2>Version History</h2>
      <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
        {versionHistory.map((version, idx) => (
          <div key={idx} style={{ border: '1px solid #ccc', margin: '10px', padding: '10px' }}>
            <p><strong>Version {idx + 1}</strong> - {new Date(version.timestamp).toLocaleString()}</p>
            <p>Data: {version.data}</p>
            <button onClick={() => handleRecoveryData(version)}>Recover This Version</button>
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;
