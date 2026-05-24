import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { connect, hash, signers } from '@hyperledger/fabric-gateway';
import * as grpc from '@grpc/grpc-js';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as jwt from 'jsonwebtoken';

const app = express();

app.use(express.json());
app.use(cors());

const NETWORK_PATH = path.resolve(process.env.HOME!, 'fabric-samples/test-network');

const CRYPTO_PATH = path.join(
  NETWORK_PATH,
  'organizations/peerOrganizations/org1.example.com'
);

const TLS_CERT = path.join(
  CRYPTO_PATH,
  'tlsca/tlsca.org1.example.com-cert.pem'
);

const CERT_PATH = path.join(
  CRYPTO_PATH,
  'users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem'
);

const KEY_DIR = path.join(
  CRYPTO_PATH,
  'users/Admin@org1.example.com/msp/keystore'
);

const JWT_SECRET =
  process.env.JWT_SECRET || 'chaintrace-nist-secret-key-2026';

interface JwtPayload {
  supplierID: string;
  name: string;
  role: string;
  email?: string;
}

declare global {
  namespace Express {
    interface Request {
      jwtUser?: JwtPayload;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGSTASH
// ─────────────────────────────────────────────────────────────────────────────

const LOGSTASH_URL = 'http://127.0.0.1:5000';

async function sendToLogstash(eventData: object): Promise<void> {
  try {
    const response = await fetch(LOGSTASH_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ...eventData,
        source: 'ChainTrace-API',
        timestamp: new Date().toISOString(),
        network: 'mychannel',
        chaincode: 'traceability',
      }),
    });

    if (!response.ok) {
      console.error(`[Logstash] ${response.status}`);
    } else {
      console.log(
        `[SIEM] ${(eventData as any).function} relayé`
      );
    }
  } catch (e: any) {
    console.warn(`Logstash indispo: ${e.message}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FABRIC CONNECTION
// ─────────────────────────────────────────────────────────────────────────────

async function getContract() {

  const client = new grpc.Client(
    'localhost:7051',
    grpc.credentials.createSsl(
      fs.readFileSync(TLS_CERT)
    ),
    {
      'grpc.ssl_target_name_override':
        'peer0.org1.example.com',
    }
  );

  const keyFiles = fs.readdirSync(KEY_DIR);

  const privateKey = crypto.createPrivateKey(
    fs.readFileSync(path.join(KEY_DIR, keyFiles[0]))
  );

  const certPem = fs
    .readFileSync(CERT_PATH)
    .toString();

  const gateway = connect({
    client,

    identity: {
      mspId: 'Org1MSP',
      credentials: Buffer.from(certPem),
    },

    signer: signers.newPrivateKeySigner(privateKey),

    hash: hash.sha256,
  });

  const network = gateway.getNetwork('mychannel');

  const contract = network.getContract('traceability');

  return {
    gateway,
    contract,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// JWT MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────

app.use(
  (
    req: Request,
    _res: Response,
    next: NextFunction
  ) => {

    const header = req.headers.authorization;

    if (header?.startsWith('Bearer ')) {
      try {
        req.jwtUser = jwt.verify(
          header.slice(7),
          JWT_SECRET
        ) as JwtPayload;
      } catch {}
    }

    next();
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// AUTO SYNC USER ON CHAIN
// ─────────────────────────────────────────────────────────────────────────────

async function ensureUserOnChain(
  supplierID: string,
  role: string,
  name: string
): Promise<void> {

  const { gateway, contract } = await getContract();

  try {

    try {

      await contract.submitTransaction(
        'IssueCertificate',
        supplierID,
        name || supplierID,
        '9.0'
      );

      console.log(
        `[SYNC] ✅ Certificat créé: ${supplierID}`
      );

    } catch (e: any) {

      if (
        !e.message?.includes('already') &&
        !e.message?.includes('déjà')
      ) {
        console.warn(
          `[SYNC] Cert warning: ${e.message}`
        );
      }
    }

    let currentRole: string | null = null;
    let isActive = false;

    try {

      const roleData =
        await contract.evaluateTransaction(
          'GetRole',
          supplierID
        );

      const parsed = JSON.parse(
        Buffer.from(roleData).toString('utf8')
      );

      currentRole = parsed.Role;
      isActive = parsed.IsActive;

    } catch {}

    if (!isActive || currentRole !== role) {

      await contract.submitTransaction(
        'AssignRole',
        supplierID,
        role
      );

      console.log(
        `[SYNC] ✅ Rôle assigné: ${supplierID} → ${role}`
      );

    } else {

      console.log(
        `[SYNC] Rôle OK: ${supplierID} = ${role}`
      );
    }

  } finally {
    await gateway.close();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// INVOKE
// ─────────────────────────────────────────────────────────────────────────────
async function invoke(
  res: Response,
  req: Request,
  fn: string,
  ...args: string[]
) {
  const user = req.jwtUser;

  if (user && user.supplierID) {
    try {
      await ensureUserOnChain(
        user.supplierID,
        user.role,
        user.name || user.supplierID
      );
    } catch (syncErr: any) {
      console.error(`[SYNC CORRELATION ERROR] ❌ ${syncErr.message}`);
    }
  }

  try {
    const { gateway, contract } = await getContract();
    let result: Uint8Array;

    if (user && user.supplierID) {
      const transientData = {
        callerID: Buffer.from(user.supplierID.trim()),
      };

      const proposal = contract.newProposal(fn, {
        arguments: args,
        transientData,
      });

      const endorsed = await proposal.endorse();
      const submitted = await endorsed.submit();
      result = submitted.getResult();
    } else {
      result = await contract.submitTransaction(fn, ...args);
    }

    await gateway.close();

    const text = Buffer.from(result).toString('utf8');
    let parsed: any = {};
    try { parsed = JSON.parse(text); } catch {}

    // Préparation du log pour Logstash
    // ── 🚨 LE BLOC CORRIGÉ COMMENCE ICI 🚨 ────────────────────────────────────
    const isAnomalyFunction = (fn === 'HandleSupplierAnomaly');

    const eventLog = {
      function: fn,
      supplierID: user?.supplierID || parsed.SupplierID || 'org1admin',
      success: true,
      recordID: parsed.ID || '',
      productID: parsed.ProductID || '',
      certStatus: parsed.Status || 'VALID',
      riskFlag: parsed.RiskFlag || (isAnomalyFunction ? true : false),

      // On force le statut à 'FAIL' pour l'appel SOAR afin d'harmoniser Kibana
      qualityStatus: isAnomalyFunction ? 'FAIL' : (parsed.QualityStatus || 'PASS'),

      // Extraction dynamique du score global calculé ou de la note produit
      qualityScore: parsed.QualityScore ? parseFloat(parsed.QualityScore) : (parsed.QualityScore || null),

      carbonAlert: parsed.Carbon?.alert || false,
      carbonMessage: parsed.Carbon?.alertMessage || '',
      co2Kg: parsed.Carbon?.co2Kg || 0,
    };
    // ──  ──────────────────────────────────────
    await sendToLogstash(eventLog);

    // ── 🚨 LE NOUVEAU DÉCLENCHEUR SOAR PLAT ET SÉPARÉ POUR N8N 🚨 ────
    if (eventLog.qualityStatus === 'FAIL' || eventLog.carbonAlert === true) {
      console.log(`\n[🚨 SOAR TRIGGER] Anomalie détectée ! Routage vers le workflow n8n...`);

      const N8N_WEBHOOK_URL = 'http://localhost:5678/webhook-test/blockchain-alert';

      // Séparation stricte et nettoyage pour éviter toute pollution ou collage dans n8n
      const alertPayload = {
        alertType: eventLog.qualityStatus === 'FAIL' ? 'VIOLATION_QUALITE' : 'DEPASSEMENT_CARBON_NIST',
        severity: 'CRITICAL',
        timestamp: new Date().toISOString(),
        supplierID: String(eventLog.supplierID).trim().replace(/['"]+/g, ''), // Nettoyé et isolé
        productID: String(eventLog.productID).trim().replace(/['"]+/g, ''),   // Nettoyé et isolé
        qualityStatus: eventLog.qualityStatus,
        // ── 🚨U SCORE DANS LE PAYLOAD DU WEBHOOK N8N 🚨 ──────────────────
        qualityScore: eventLog.qualityScore || 0,
  // ────────────────────────────────────────────────────────────────────────
        co2Emitted: `${eventLog.co2Kg} kg`,
        blockchainMessage: eventLog.carbonMessage || 'Alerte conformité levée'
      };

      fetch(N8N_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alertPayload)
      }).then(n8nRes => {
        if(n8nRes.ok) console.log(`[🚀 SOAR] Payload d'alerte transmis avec succès à n8n !`);
        else console.error(`[❌ SOAR] Erreur n8n, statut : ${n8nRes.status}`);
      }).catch(e => console.warn(`[❌ SOAR] Impossible de joindre n8n: ${e.message}`));
    }

    try {
      res.json({ success: true, data: JSON.parse(text) });
    } catch {
      res.json({ success: true, message: text });
    }

  } catch (err: any) {
    let cleanMsg = err.message || String(err);
    if (err.details && err.details.length > 0) cleanMsg = err.details[0].message || cleanMsg;
    cleanMsg = cleanMsg.replace(/^Error:\s*/, '').trim();

    await sendToLogstash({
      function: fn,
      supplierID: user?.supplierID || 'unknown',
      success: false,
      error: cleanMsg
    });

    res.status(400).json({ success: false, error: cleanMsg });
  }
}
// ─────────────────────────────────────────────────────────────────────────────
// QUERY
// ─────────────────────────────────────────────────────────────────────────────

async function query(
  res: Response,
  fn: string,
  ...args: string[]
) {

  try {

    const { gateway, contract } =
      await getContract();

    const result =
      await contract.evaluateTransaction(
        fn,
        ...args
      );

    await gateway.close();

    const text = Buffer.from(result)
      .toString('utf8')
      .trim();

    try {

      res.json(JSON.parse(text));

    } catch {

      if (text === 'true') {
        return res.json({
          isValid: true,
        });
      }

      if (text === 'false') {
        return res.json({
          isValid: false,
        });
      }

      res.json({
        message: text,
      });
    }

  } catch (err: any) {

    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────────────────────────────


// ── 🚨 ROUTE SOAR : GESTION DES AVERTISSEMENTS (3-STRIKE POLICY) ───────────
app.post('/certificate/handle-anomaly', (req, res) => {
  const { supplierID, alertID } = req.body;

  if (!supplierID || !alertID) {
    return res.status(400).json({
      success: false,
      error: 'supplierID et alertID requis pour appliquer un avertissement',
    });
  }

  // Appelle la nouvelle fonction de ton Chaincode Fabric
  invoke(
    res,
    req,
    'HandleSupplierAnomaly', // Nom exact de la fonction de ton Smart Contract
    String(supplierID),
    String(alertID)
  );
});





app.post('/role/assign', (req, res) => {

  const { supplierID, role } =
    req.body;

  if (!supplierID || !role) {

    return res.status(400).json({
      success: false,
      error:
        'supplierID et role requis',
    });
  }

  invoke(
    res,
    req,
    'AssignRole',
    String(supplierID),
    String(role)
  );
});

app.post('/role/revoke', (req, res) => {

  const { supplierID, reason } =
    req.body;

  if (!supplierID) {

    return res.status(400).json({
      success: false,
      error: 'supplierID requis',
    });
  }

  invoke(
    res,
    req,
    'RevokeRole',
    String(supplierID),
    String(
      reason ||
      'Révocation manuelle'
    )
  );
});

app.get(
  '/role/:supplierID',
  (req, res) =>
    query(
      res,
      'GetRole',
      String(req.params.supplierID)
    )
);

app.post('/make', (req, res) => {

  const {
    productID,
    batchID,
    productType,
    machineID,
    quantityProduced,
    qualityScore,
    locationCity,
    cost,
    currency,
  } = req.body;

  invoke(
    res,
    req,
    'CreateMake',
    String(productID),
    String(batchID || 'BATCH_001'),
    String(productType || 'Standard'),
    String(machineID || 'MACHINE_001'),
    String(quantityProduced || '100'),
    String(qualityScore || '9.0'),
    String(locationCity || 'Fes'),
    String(cost || '0'),
    String(currency || 'MAD')
  );
});

app.post('/transport', (req, res) => {

  const {
    previousRecordID,
    vehicleID,
    transportMode,
    origin,
    destination,
    quantityShipped,
    originCity,
    destCity,
    transportCost,
    currency,
  } = req.body;

  invoke(
    res,
    req,
    'CreateTransport',
    String(previousRecordID),
    String(vehicleID || 'VEHICLE_001'),
    String(transportMode || 'Road'),
    String(origin),
    String(destination),
    String(quantityShipped || '100'),
    String(originCity || origin),
    String(destCity || destination),
    String(transportCost || '0'),
    String(currency || 'MAD')
  );
});

app.post('/receive', (req, res) => {

  const {
    transportID,
    quantityReceived,
    conditionStatus,
    locationCity,
  } = req.body;

  invoke(
    res,
    req,
    'CreateReceive',
    String(transportID),
    String(quantityReceived || '100'),
    String(conditionStatus || 'OK'),
    String(locationCity || 'Casablanca')
  );
});

app.post('/assemble', (req, res) => {

  const {
    previousRecordID,
    productID,
    components,
    quantityAssembled,
    qualityCheck,
    locationCity,
    assemblyCost,
    currency,
  } = req.body;

  invoke(
    res,
    req,
    'CreateAssemble',
    String(previousRecordID),
    String(productID),
    String(components || '[]'),
    String(quantityAssembled || '100'),
    String(qualityCheck || 'PASS'),
    String(locationCity || 'Fes'),
    String(assemblyCost || '0'),
    String(currency || 'MAD')
  );
});

app.post('/employ', (req, res) => {

  const {
    receiveID,
    deliveryStatus,
    finalLocation,
    purpose,
    locationCity,
    totalValue,
    currency,
  } = req.body;

  invoke(
    res,
    req,
    'CreateEmploy',
    String(receiveID),
    String(deliveryStatus || 'On Time'),
    String(finalLocation),
    String(purpose),
    String(locationCity || finalLocation),
    String(totalValue || '0'),
    String(currency || 'MAD')
  );
});

app.get(
  '/history/:productID',
  (req, res) =>
    query(
      res,
      'GetTraceHistory',
      String(req.params.productID)
    )
);

app.get(
  '/record/:id',
  (req, res) =>
    query(
      res,
      'ReadRecord',
      String(req.params.id)
    )
);



// ── 🚨  ROUTE DE RÉVOCATION PKI ICI ──────────────────────────
app.post('/certificate/revoke', (req, res) => {
  const { supplierID, reason } = req.body;

  if (!supplierID) {
    return res.status(400).json({
      success: false,
      error: 'supplierID requis pour la révocation',
    });
  }

  // Appelle la fonction correspondante de ton Chaincode Fabric
  invoke(
    res,
    req,
    'RevokeCertificate', // Vérifie bien que c'est le nom exact dans ton chaincode (ex: RevokeCertificate)
    String(supplierID),
    String(reason || 'Révocation automatique SOAR')
  );
});
// ─────────────────────────────────────────────────────────────────────────



app.get(
  '/certificate/verify/:supplierID',
  (req, res) =>
    query(
      res,
      'VerifyCertificate',
      String(req.params.supplierID)
    )
);

app.get(
  '/certificate/:supplierID',
  (req, res) =>
    query(
      res,
      'GetCertificate',
      String(req.params.supplierID)
    )
);

// ── 🔐 AJOUT DE LA ROUTE D'ÉMISSION PKI ──────────────────────────────────────
app.post('/certificate/issue', (req, res) => {
  const { supplierID, supplierName, qualityScore } = req.body;

  if (!supplierID || !supplierName) {
    return res.status(400).json({
      success: false,
      error: 'supplierID et supplierName requis',
    });
  }

  invoke(
    res,
    req,
    'IssueCertificate', // Nom exact dans ton chaincode
    String(supplierID),
    String(supplierName),
    String(qualityScore || '8.5')
  );
});

// ── 📊  LA ROUTE DE MISE À JOUR DU SCORE PKI ────────────────────────
app.post('/certificate/update-score', (req, res) => {
  const { supplierID, defectRate, deliveryOnTimeRate } = req.body;

  if (!supplierID) {
    return res.status(400).json({
      success: false,
      error: 'supplierID requis',
    });
  }

  invoke(
    res,
    req,
    'UpdateSupplierScore', // Nom exact dans ton chaincode
    String(supplierID),
    String(defectRate || '0'),
    String(deliveryOnTimeRate || '100')
  );
});

// ─────────────────────────────────────────────────────────────────────────




app.get(
  '/carbon/:productID',
  (req, res) =>
    query(
      res,
      'GetCarbonReport',
      String(req.params.productID)
    )
);
// ─────────────────────────────────────────────────────────────────────────

app.get('/', (_req, res) => {

  res.json({
    message:
      'API ChainTrace v9.0 active',
    status: 'ok',
  });
});

app.listen(
  3000,
  '0.0.0.0',
  () => {
    console.log(
      '✅ API active sur http://localhost:3000'
    );
  }
);
