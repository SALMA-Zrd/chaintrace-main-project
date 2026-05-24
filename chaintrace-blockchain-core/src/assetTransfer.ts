import { Context, Contract, Info, Transaction } from 'fabric-contract-api';
import * as crypto from 'crypto';

// ============================================================
// CLASSES DE DONNÉES — PHASE 4 : GPS + FINANCES + CARBONE
// ============================================================

// Coordonnées GPS
export class GPSCoords {
  public lat: number = 0;
  public lng: number = 0;
  public city: string = '';
}

// Données financières
export class FinancialData {
  public cost: number = 0;
  public currency: string = 'MAD';
  public description: string = '';
}

// Empreinte carbone
export class CarbonData {
  public co2Kg: number = 0;
  public transportMode: string = '';
  public distanceKm: number = 0;
  public carbonScore: string = ''; // A, B, C, D, F
  public alert: boolean = false;
  public alertMessage: string = '';
  public nistThresholdKg: number = 0;
}

// Classes de base (inchangées Phase 1-3)
export class TraceRecord {
  public ID: string = '';
  public Type: string = '';
  public ProductID: string = '';
  public ActorID: string = '';
  public PreviousHash: string = '';
  public Timestamp: string = '';
  public Hash: string = '';
  public Signature: string = '';
}

export class Certificate {
  public SupplierID: string = '';
  public SupplierName: string = '';
  public Status: string = '';
  public QualityScore: number = 0;
  public DefectRate: number = 0;
  public DeliveryOnTimeRate: number = 0;
  public IssuedDate: string = '';
  public ExpiryDate: string = '';
  public LastUpdate: string = '';
  public RevocationReason: string = '';
  WarningCount: number=0; 
}

export class RoleRecord {
  public SupplierID: string = '';
  public Role: string = '';
  public AssignedBy: string = '';
  public AssignedDate: string = '';
  public IsActive: boolean = false;
  public RevokedReason: string = '';
}

// ── PHASE 4 : MakeRecord enrichi ──
export class MakeRecord extends TraceRecord {
  public BatchID: string = '';
  public ProductType: string = '';
  public MachineID: string = '';
  public QuantityProduced: number = 0;
  public QualityScore: number = 0;
  public QualityStatus: string = '';
  public CertificateID: string = '';
  // Phase 4
  public Location: GPSCoords = new GPSCoords();
  public Financial: FinancialData = new FinancialData();
  public Carbon: CarbonData = new CarbonData();
}

// ── PHASE 4 : TransportRecord enrichi ──
export class TransportRecord extends TraceRecord {
  public PreviousRecordID: string = '';
  public VehicleID: string = '';
  public TransportMode: string = '';
  public Origin: string = '';
  public Destination: string = '';
  public QuantityShipped: number = 0;
  public Status: string = '';
  public CertificateID: string = '';
  // Phase 4
  public OriginCoords: GPSCoords = new GPSCoords();
  public DestCoords: GPSCoords = new GPSCoords();
  public DistanceKm: number = 0;
  public RouteWaypoints: string = ''; // JSON array of coords
  public Financial: FinancialData = new FinancialData();
  public Carbon: CarbonData = new CarbonData();
}

export class ReceiveRecord extends TraceRecord {
  public TransportID: string = '';
  public QuantityReceived: number = 0;
  public QuantityExpected: number = 0;
  public QuantityGap: number = 0;
  public ConditionStatus: string = '';
  public ReceiveValidation: boolean = false;
  public CertificateID: string = '';
  // Phase 4
  public Location: GPSCoords = new GPSCoords();
  public Carbon: CarbonData = new CarbonData();
}

export class AssembleRecord extends TraceRecord {
  public MakeID: string = '';
  public Components: string = '';
  public QuantityAssembled: number = 0;
  public QualityCheck: string = '';
  public CertificateID: string = '';
  // Phase 4
  public Location: GPSCoords = new GPSCoords();
  public Financial: FinancialData = new FinancialData();
  public Carbon: CarbonData = new CarbonData();
}

// ── PHASE 4 : EmployRecord enrichi ──
export class EmployRecord extends TraceRecord {
  public ReceiveID: string = '';
  public DeliveryStatus: string = '';
  public RiskFlag: boolean = false;
  public FinalLocation: string = '';
  public Purpose: string = '';
  public CertificateID: string = '';
  // Phase 4
  public LocationCoords: GPSCoords = new GPSCoords();
  public Financial: FinancialData = new FinancialData();
  public Carbon: CarbonData = new CarbonData();
  public TotalChainCO2Kg: number = 0;
  public GlobalCarbonAlert: boolean = false;
}

export class ValidationReport {
  public IsValid: boolean = false;
  public ChainLength: number = 0;
  public AnomaliesDetected: string[] = [];
  public IntegrityScore: number = 0;
  public Details: string[] = [];
}

@Info({ title: 'TraceabilityV7', description: 'NIST Supply Chain Phase 4 - GPS+Finance+Carbon' })
export class TraceabilityContract extends Contract {

  private readonly VALID_ROLES = ['Admin','Maker','Transporter','Receiver','Assembler','Employer'];

  // ── CO2 par mode de transport (kg/tonne/km) ────────────────
  private readonly CO2_FACTORS: Record<string, number> = {
    Road: 0.096,   // Camion
    Rail: 0.028,   // Train
    Sea:  0.016,   // Bateau
  };

  // ── Seuils NIST CO2 par mode (kg total) ───────────────────
  private readonly NIST_THRESHOLDS: Record<string, number> = {
    Road: 500,
    Rail: 150,
    Sea:  80,
    Make: 200,
    Assemble: 100,
  };

  // ── Villes marocaines avec coordonnées GPS réelles ─────────
  private readonly MOROCCO_CITIES: Record<string, {lat:number, lng:number}> = {
    'Fes':         { lat: 34.0181, lng: -5.0078 },
    'Casablanca':  { lat: 33.5731, lng: -7.5898 },
    'Rabat':       { lat: 34.0209, lng: -6.8416 },
    'Marrakech':   { lat: 31.6295, lng: -7.9811 },
    'Tanger':      { lat: 35.7595, lng: -5.8340 },
    'Agadir':      { lat: 30.4278, lng: -9.5981 },
    'Meknes':      { lat: 33.8935, lng: -5.5473 },
    'Oujda':       { lat: 34.6867, lng: -1.9114 },
    'Kenitra':     { lat: 34.2610, lng: -6.5802 },
    'Nador':       { lat: 35.1740, lng: -2.9287 },
  };

  // ── Calcul distance Haversine entre 2 coordonnées ──────────
  private haversineKm(lat1:number, lng1:number, lat2:number, lng2:number): number {
    const R = 6371;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLng = (lng2 - lng1) * Math.PI / 180;
    const a = Math.sin(dLat/2)*Math.sin(dLat/2) +
              Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*
              Math.sin(dLng/2)*Math.sin(dLng/2);
    return Math.round(R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)));
  }

  // ── Calcul CO2 transport ───────────────────────────────────
  private calcTransportCO2(distanceKm:number, mode:string, quantityTons:number): CarbonData {
    const factor    = this.CO2_FACTORS[mode] || 0.096;
    const threshold = this.NIST_THRESHOLDS[mode] || 500;
    const co2Kg     = Math.round(factor * distanceKm * quantityTons * 100) / 100;
    const alert     = co2Kg > threshold;
    const score     = co2Kg <= threshold * 0.3 ? 'A' :
                      co2Kg <= threshold * 0.6 ? 'B' :
                      co2Kg <= threshold * 0.8 ? 'C' :
                      co2Kg <= threshold        ? 'D' : 'F';
    const carbon = new CarbonData();
    carbon.co2Kg          = co2Kg;
    carbon.transportMode  = mode;
    carbon.distanceKm     = distanceKm;
    carbon.carbonScore    = score;
    carbon.alert          = alert;
    carbon.alertMessage   = alert ? `ALERTE NIST : CO2 ${co2Kg}kg dépasse seuil ${threshold}kg (mode ${mode})` : '';
    carbon.nistThresholdKg = threshold;
    return carbon;
  }

  // ── Calcul CO2 fabrication ─────────────────────────────────
  private calcManufactureCO2(quantity:number, qualityScore:number, type:string): CarbonData {
    const threshold = this.NIST_THRESHOLDS[type] || 200;
    // Estimation : meilleure qualité = process plus propre
    const co2PerUnit = type === 'Assemble' ? 0.8 : 1.5;
    const efficiency = qualityScore / 10;
    const co2Kg      = Math.round(co2PerUnit * quantity * (2 - efficiency) * 100) / 100;
    const alert      = co2Kg > threshold;
    const score      = co2Kg <= threshold*0.3 ? 'A' : co2Kg <= threshold*0.6 ? 'B' :
                       co2Kg <= threshold*0.8 ? 'C' : co2Kg <= threshold ? 'D' : 'F';
    const carbon = new CarbonData();
    carbon.co2Kg          = co2Kg;
    carbon.transportMode  = type;
    carbon.distanceKm     = 0;
    carbon.carbonScore    = score;
    carbon.alert          = alert;
    carbon.alertMessage   = alert ? `ALERTE NIST : CO2 fabrication ${co2Kg}kg > seuil ${threshold}kg` : '';
    carbon.nistThresholdKg = threshold;
    return carbon;
  }

  // ── Résoudre coordonnées GPS d'une ville ───────────────────
  private resolveCity(cityName: string): GPSCoords {
    const coords = new GPSCoords();
    coords.city  = cityName;
    const known  = this.MOROCCO_CITIES[cityName];
    if (known) { coords.lat = known.lat; coords.lng = known.lng; }
    return coords;
  }

  // ── Helpers communs ────────────────────────────────────────
  private getTimestamp(ctx: Context): string {
    const ts = ctx.stub.getTxTimestamp();
    return new Date((ts.seconds.low*1000)+Math.round(ts.nanos/1e6)).toISOString();
  }
  private calculateHash(record: TraceRecord): string {
    return crypto.createHash('sha256').update(JSON.stringify({
      ID:record.ID, Type:record.Type, ProductID:record.ProductID,
      ActorID:record.ActorID, PreviousHash:record.PreviousHash, Timestamp:record.Timestamp
    })).digest('hex');
  }
  private generateID(ctx: Context, prefix: string): string {
    const txID = ctx.stub.getTxID().substring(0,8).toUpperCase();
    const ts   = ctx.stub.getTxTimestamp();
    const date = new Date(ts.seconds.low*1000).toISOString().slice(0,10).replace(/-/g,'');
    return `${prefix}_${date}_${txID}`;
  }
  private async getRecord(ctx: Context, id: string): Promise<TraceRecord> {
    const data = await ctx.stub.getState(id);
    if (!data||data.length===0) throw new Error(`Enregistrement "${id}" introuvable`);
    return JSON.parse(Buffer.from(data).toString('utf8')) as TraceRecord;
  }
  private extractSupplierID(fullID: string): string {
    const match = fullID.match(/CN=([^:,/]+)/);
    return match ? match[1] : fullID.substring(0,32);
  }
  private calculateQualityScore(d:number,del:number,old:number): number {
    return Math.round(((Math.max(0,10-d*2))*0.4+(del/10)*0.4+old*0.2)*100)/100;
  }



// ──  verifyAccess dans assetTransfer.ts ──────────────


private async verifyAccess(ctx: Context, requiredRole: string): Promise<string> {
    let supplierID: string = '';

    try {
        // Lecture de la map transiente envoyée par app.ts
        const transientMap = ctx.stub.getTransient();

        if (transientMap && transientMap.has('callerID')) {
            const callerBuf = transientMap.get('callerID');
            if (callerBuf && callerBuf.length > 0) {
                // CORRECTION 1 : Conversion robuste de Uint8Array en chaîne UTF-8 via Buffer.from
                supplierID = Buffer.from(callerBuf).toString('utf8');
                // Enlever les potentiels caractères de contrôle ou guillemets résiduels
                supplierID = supplierID.replace(/['"]+/g, '').trim();
            }
        }
    } catch (transientError: any) {
        // CORRECTION 2 : Typage explicite ': any' pour pouvoir lire .message
        console.log(`[Chaincode RBAC] Erreur de lecture transiente: ${transientError.message}`);
    }

    // Fallback de sécurité : Si aucune identité transiente n'est fournie, on prend l'identité du certificat de l'API
    if (!supplierID) {
        const actorFullID = ctx.clientIdentity.getID();
        supplierID = this.extractSupplierID(actorFullID);
    }

    // 1. Vérification du certificat d'existence du fournisseur sur le Ledger
    const certCheckStr = await this.VerifyCertificate(ctx, supplierID);
    const certCheck = JSON.parse(certCheckStr);
    if (!certCheck.isValid) {
        throw new Error(`Accès refusé — Certificat invalide pour "${supplierID}" : ${certCheck.reason}`);
    }

    // 2. Vérification du rôle stocké sur le Ledger de la Blockchain
    const roleData = await ctx.stub.getState(`ROLE_${supplierID}`);
    if (!roleData || roleData.length === 0) {
        throw new Error(`Accès refusé — Aucun rôle assigné sur la blockchain pour "${supplierID}"`);
    }

    const role: RoleRecord = JSON.parse(Buffer.from(roleData).toString('utf8'));
    if (!role.IsActive) {
        throw new Error(`Accès refusé — Rôle révoqué pour "${supplierID}" : ${role.RevokedReason}`);
    }

    if (role.Role !== requiredRole) {
        throw new Error(`Accès refusé — L'utilisateur "${supplierID}" détient le rôle "${role.Role}" sur la blockchain, mais le rôle "${requiredRole}" est requis.`);
    }

    return supplierID;
}



  // ============================================================
  // PHASE 4 — FONCTIONS NIST ENRICHIES
  // ============================================================

  @Transaction()
  public async CreateMake(
    ctx: Context,
    productID: string, batchID: string, productType: string,
    machineID: string, quantityProduced: string, qualityScore: string,
    // Phase 4 — GPS
    locationCity: string,
    // Phase 4 — Finances
    cost: string, currency: string,
  ): Promise<string> {
    const supplierID  = await this.verifyAccess(ctx, 'Maker');
    const actorFullID = ctx.clientIdentity.getID();
    const qty   = parseInt(quantityProduced);
    const score = parseFloat(qualityScore);

    // GPS
    const location = this.resolveCity(locationCity || 'Fes');

    // Finances
    const financial = new FinancialData();
    financial.cost        = parseFloat(cost) || 0;
    financial.currency    = currency || 'MAD';
    financial.description = `Fabrication ${productType} x${qty}`;

    // Carbone Phase 4
    const carbon = this.calcManufactureCO2(qty, score, 'Make');

    const record       = new MakeRecord();
    record.ID          = this.generateID(ctx, 'MAKE');
    record.Type        = 'Make';
    record.ProductID   = productID;
    record.ActorID     = actorFullID;
    record.PreviousHash = '';
    record.Timestamp   = this.getTimestamp(ctx);
    record.BatchID     = batchID;
    record.ProductType = productType;
    record.MachineID   = machineID;
    record.QuantityProduced = qty;
    record.QualityScore     = score;
    record.QualityStatus    = score >= 7.0 ? 'PASS' : 'FAIL';
    record.CertificateID    = supplierID;
    record.Signature        = actorFullID;
    record.Location         = location;
    record.Financial        = financial;
    record.Carbon           = carbon;
    record.Hash             = this.calculateHash(record);

    await ctx.stub.putState(record.ID, Buffer.from(JSON.stringify(record)));
    if (carbon.alert) {
      await ctx.stub.setEvent('CarbonAlert', Buffer.from(JSON.stringify({
        recordID: record.ID, type:'Make', co2Kg: carbon.co2Kg,
        message: carbon.alertMessage, city: locationCity
      })));
    }
    await ctx.stub.setEvent('MakeRecordCreated', Buffer.from(JSON.stringify({
      id: record.ID, productID, certID: supplierID,
      co2Kg: carbon.co2Kg, carbonScore: carbon.carbonScore,
      location: location.city, cost: financial.cost
    })));
    return JSON.stringify(record);
  }

  @Transaction()
  public async CreateTransport(
    ctx: Context,
    previousRecordID: string, vehicleID: string,
    transportMode: string,   // Road | Rail | Sea
    origin: string, destination: string,
    quantityShipped: string,
    // Phase 4 — GPS (noms de villes marocaines)
    originCity: string, destCity: string,
    // Phase 4 — Finances
    transportCost: string, currency: string,
  ): Promise<string> {
    const supplierID     = await this.verifyAccess(ctx, 'Transporter');
    const actorFullID    = ctx.clientIdentity.getID();
    const previousRecord = await this.getRecord(ctx, previousRecordID);
    const qty            = parseInt(quantityShipped);

    // GPS — résolution coordonnées + calcul distance
    const originCoords = this.resolveCity(originCity || origin);
    const destCoords   = this.resolveCity(destCity || destination);
    const distanceKm   = this.haversineKm(
      originCoords.lat, originCoords.lng, destCoords.lat, destCoords.lng
    );
    // Waypoints intermédiaires simulés (point médian)
    const midLat = (originCoords.lat + destCoords.lat) / 2;
    const midLng = (originCoords.lng + destCoords.lng) / 2;
    const waypoints = JSON.stringify([
      [originCoords.lat, originCoords.lng],
      [midLat, midLng],
      [destCoords.lat, destCoords.lng]
    ]);

    // Finances
    const financial = new FinancialData();
    financial.cost        = parseFloat(transportCost) || 0;
    financial.currency    = currency || 'MAD';
    financial.description = `Transport ${transportMode} : ${originCity} → ${destCity} (${distanceKm}km)`;

    // Carbone — quantité en tonnes (qty / 1000 si en kg)
    const quantityTons = qty / 1000 || 0.1;
    const carbon       = this.calcTransportCO2(distanceKm, transportMode, quantityTons);

    const record               = new TransportRecord();
    record.ID                  = this.generateID(ctx, 'TRANSPORT');
    record.Type                = 'Transport';
    record.ProductID           = previousRecord.ProductID;
    record.ActorID             = actorFullID;
    record.PreviousHash        = previousRecord.Hash;
    record.Timestamp           = this.getTimestamp(ctx);
    record.PreviousRecordID    = previousRecordID;
    record.VehicleID           = vehicleID;
    record.TransportMode       = transportMode;
    record.Origin              = origin;
    record.Destination         = destination;
    record.QuantityShipped     = qty;
    record.Status              = 'In Transit';
    record.CertificateID       = supplierID;
    record.Signature           = actorFullID;
    record.OriginCoords        = originCoords;
    record.DestCoords          = destCoords;
    record.DistanceKm          = distanceKm;
    record.RouteWaypoints      = waypoints;
    record.Financial           = financial;
    record.Carbon              = carbon;
    record.Hash                = this.calculateHash(record);

    await ctx.stub.putState(record.ID, Buffer.from(JSON.stringify(record)));
    if (carbon.alert) {
      await ctx.stub.setEvent('CarbonAlert', Buffer.from(JSON.stringify({
        recordID: record.ID, type:'Transport', co2Kg: carbon.co2Kg,
        message: carbon.alertMessage, route: `${originCity}→${destCity}`
      })));
    }
    return JSON.stringify(record);
  }

  @Transaction()
  public async CreateReceive(
    ctx: Context,
    transportID: string, quantityReceived: string, conditionStatus: string,
    // Phase 4 — GPS
    locationCity: string,
  ): Promise<string> {
    const supplierID      = await this.verifyAccess(ctx, 'Receiver');
    const actorFullID     = ctx.clientIdentity.getID();
    const transportRecord = await this.getRecord(ctx, transportID);
    const qtyReceived     = parseInt(quantityReceived);
    const qtyExpected     = (transportRecord as any).QuantityShipped || 0;

    const location = this.resolveCity(locationCity || 'Casablanca');
    // CO2 réception = faible (manutention)
    const carbon = new CarbonData();
    carbon.co2Kg = Math.round(qtyReceived * 0.002 * 100) / 100;
    carbon.carbonScore = 'A';  carbon.alert = false;
    carbon.nistThresholdKg = 50;

    const record = new ReceiveRecord();
    record.ID               = this.generateID(ctx, 'RECEIVE');
    record.Type             = 'Receive';
    record.ProductID        = transportRecord.ProductID;
    record.ActorID          = actorFullID;
    record.PreviousHash     = transportRecord.Hash;
    record.Timestamp        = this.getTimestamp(ctx);
    record.TransportID      = transportID;
    record.QuantityReceived = qtyReceived;
    record.QuantityExpected = qtyExpected;
    record.QuantityGap      = qtyReceived - qtyExpected;
    record.ConditionStatus  = conditionStatus;
    record.ReceiveValidation = (record.QuantityGap===0 && conditionStatus==='OK');
    record.CertificateID    = supplierID;
    record.Signature        = actorFullID;
    record.Location         = location;
    record.Carbon           = carbon;
    record.Hash             = this.calculateHash(record);
    await ctx.stub.putState(record.ID, Buffer.from(JSON.stringify(record)));
    return JSON.stringify(record);
  }

  @Transaction()
  public async CreateAssemble(
    ctx: Context,
    previousRecordID: string, productID: string,
    components: string, quantityAssembled: string, qualityCheck: string,
    // Phase 4
    locationCity: string, assemblyCost: string, currency: string,
  ): Promise<string> {
    const supplierID     = await this.verifyAccess(ctx, 'Assembler');
    const actorFullID    = ctx.clientIdentity.getID();
    const previousRecord = await this.getRecord(ctx, previousRecordID);
    const qty            = parseInt(quantityAssembled);

    const location = this.resolveCity(locationCity || 'Fes');
    const financial = new FinancialData();
    financial.cost = parseFloat(assemblyCost)||0;  financial.currency = currency||'MAD';
    financial.description = `Assemblage x${qty} — ${qualityCheck}`;
    const carbon = this.calcManufactureCO2(qty, qualityCheck==='PASS'?8:5, 'Assemble');

    const record = new AssembleRecord();
    record.ID               = this.generateID(ctx, 'ASSEMBLE');
    record.Type             = 'Assemble';
    record.ProductID        = productID;
    record.ActorID          = actorFullID;
    record.PreviousHash     = previousRecord.Hash;
    record.Timestamp        = this.getTimestamp(ctx);
    record.MakeID           = previousRecordID;
    record.Components       = components;
    record.QuantityAssembled = qty;
    record.QualityCheck     = qualityCheck;
    record.CertificateID    = supplierID;
    record.Signature        = actorFullID;
    record.Location         = location;
    record.Financial        = financial;
    record.Carbon           = carbon;
    record.Hash             = this.calculateHash(record);
    await ctx.stub.putState(record.ID, Buffer.from(JSON.stringify(record)));
    return JSON.stringify(record);
  }

  @Transaction()
  public async CreateEmploy(
    ctx: Context,
    receiveID: string, deliveryStatus: string,
    finalLocation: string, purpose: string,
    // Phase 4
    locationCity: string, totalValue: string, currency: string,
  ): Promise<string> {
    const supplierID  = await this.verifyAccess(ctx, 'Employer');
    const actorFullID = ctx.clientIdentity.getID();
    const receiveRecord = await this.getRecord(ctx, receiveID);
    const riskFlag = (receiveRecord as any).ReceiveValidation===false ||
                     (receiveRecord as any).ConditionStatus!=='OK';

    const location = this.resolveCity(locationCity || finalLocation);
    const financial = new FinancialData();
    financial.cost = parseFloat(totalValue)||0;  financial.currency = currency||'MAD';
    financial.description = `Déploiement : ${purpose} à ${finalLocation}`;

    // Calcul CO2 total de toute la chaîne
    let totalCO2 = 0;
    let globalAlert = false;
    try {
      // Remonter la chaîne pour sommer les CO2
      const chain = await this.getChainRecords(ctx, receiveID);
      for (const r of chain) {
        const carbon = (r as any).Carbon;
        if (carbon && carbon.co2Kg) totalCO2 += carbon.co2Kg;
      }
      totalCO2 = Math.round(totalCO2 * 100) / 100;
      globalAlert = totalCO2 > 1000; // Seuil NIST global chaîne complète
    } catch(e) { /* chaîne incomplète, on continue */ }

    const carbon = new CarbonData();
    carbon.co2Kg = 0;  carbon.carbonScore = 'A';
    carbon.nistThresholdKg = 1000;

    const record = new EmployRecord();
    record.ID             = this.generateID(ctx, 'EMPLOY');
    record.Type           = 'Employ';
    record.ProductID      = receiveRecord.ProductID;
    record.ActorID        = actorFullID;
    record.PreviousHash   = receiveRecord.Hash;
    record.Timestamp      = this.getTimestamp(ctx);
    record.ReceiveID      = receiveID;
    record.DeliveryStatus = deliveryStatus;
    record.RiskFlag       = riskFlag;
    record.FinalLocation  = finalLocation;
    record.Purpose        = purpose;
    record.CertificateID  = supplierID;
    record.Signature      = actorFullID;
    record.LocationCoords = location;
    record.Financial      = financial;
    record.Carbon         = carbon;
    record.TotalChainCO2Kg = totalCO2;
    record.GlobalCarbonAlert = globalAlert;
    record.Hash           = this.calculateHash(record);

    await ctx.stub.putState(record.ID, Buffer.from(JSON.stringify(record)));
    await ctx.stub.setEvent('EmployRecordCreated', Buffer.from(JSON.stringify({
      id: record.ID, riskFlag, certID: supplierID,
      totalChainCO2: totalCO2, globalAlert,
      totalValue: financial.cost
    })));
    if (globalAlert) {
      await ctx.stub.setEvent('GlobalCarbonAlert', Buffer.from(JSON.stringify({
        recordID: record.ID, totalCO2Kg: totalCO2,
        message: `ALERTE NIST GLOBALE : CO2 chaîne complète ${totalCO2}kg > seuil 1000kg`
      })));
    }
    return JSON.stringify(record);
  }

  // ── Helper : récupérer tous les records d'une chaîne ───────
  private async getChainRecords(ctx: Context, startID: string): Promise<TraceRecord[]> {
    const records: TraceRecord[] = [];
    let currentID = startID;
    let steps = 0;
    while (currentID !== '' && steps < 20) {
      steps++;
      const record = await this.getRecord(ctx, currentID);
      records.push(record);
      if (record.PreviousHash !== '') {
        const iterator = await ctx.stub.getStateByRange('', '');
        let found = false;  let res = await iterator.next();
        while (!res.done) {
          const prev = JSON.parse(res.value.value.toString()) as TraceRecord;
          if (prev.Hash === record.PreviousHash) { found=true; currentID=prev.ID; break; }
          res = await iterator.next();
        }
        await iterator.close();
        if (!found) break;
      } else break;
    }
    return records;
  }

  // ── NOUVELLE FONCTION PHASE 4 : Rapport Carbone ───────────
  @Transaction(false)
  public async GetCarbonReport(ctx: Context, productID: string): Promise<string> {
    const iterator = await ctx.stub.getStateByRange('', '');
    const records: TraceRecord[] = [];
    let res = await iterator.next();
    while (!res.done) {
      const r = JSON.parse(res.value.value.toString()) as TraceRecord;
      if (r.ProductID === productID) records.push(r);
      res = await iterator.next();
    }
    await iterator.close();

    let totalCO2 = 0;  const alerts: string[] = [];  const steps: object[] = [];
    for (const r of records) {
      const carbon = (r as any).Carbon;
      if (carbon && carbon.co2Kg) {
        totalCO2 += carbon.co2Kg;
        steps.push({
          type: r.Type, id: r.ID, co2Kg: carbon.co2Kg,
          score: carbon.carbonScore, alert: carbon.alert,
          mode: carbon.transportMode, distanceKm: carbon.distanceKm
        });
        if (carbon.alert) alerts.push(carbon.alertMessage);
      }
    }
    totalCO2 = Math.round(totalCO2 * 100) / 100;
    const globalScore = totalCO2 <= 300 ? 'A' : totalCO2 <= 600 ? 'B' :
                        totalCO2 <= 800 ? 'C' : totalCO2 <= 1000 ? 'D' : 'F';
    return JSON.stringify({
      productID, totalCO2Kg: totalCO2,
      globalScore, globalAlert: totalCO2 > 1000,
      nistThresholdKg: 1000,
      alerts, steps,
      recommendation: totalCO2 > 1000 ?
        'Remplacer transport Road par Rail ou Sea pour réduire CO2' :
        'Empreinte carbone conforme aux seuils NIST'
    }, null, 2);
  }

  // ── PKI (Phase 2 ) ───────────────────────────────
  @Transaction()
  public async IssueCertificate(ctx:Context,supplierID:string,supplierName:string,qualityScore:string):Promise<string>{
    const score=parseFloat(qualityScore);
    if(score<7.0) throw new Error(`Score insuffisant. Minimum : 7.0`);
    const existing=await ctx.stub.getState(`CERT_${supplierID}`);
    if(existing&&existing.length>0) throw new Error(`Certificat déjà existant pour ${supplierID}`);
    const now=this.getTimestamp(ctx);
    const tsObj=ctx.stub.getTxTimestamp();
    const expiry=new Date((tsObj.seconds.low+365*24*3600)*1000).toISOString();
    const cert=new Certificate();
    cert.SupplierID=supplierID; cert.SupplierName=supplierName; cert.Status='VALID';
    cert.QualityScore=score; cert.DefectRate=0; cert.DeliveryOnTimeRate=100;
    cert.IssuedDate=now; cert.ExpiryDate=expiry; cert.LastUpdate=now; cert.RevocationReason='';
    cert.WarningCount = 0; 
    await ctx.stub.putState(`CERT_${supplierID}`,Buffer.from(JSON.stringify(cert)));
    return JSON.stringify(cert);
  }

  @Transaction()
    @Transaction()
public async HandleSupplierAnomaly(ctx: Context, supplierID: string, alertID: string): Promise<string> {
    const data = await ctx.stub.getState(`CERT_${supplierID}`);
    if (!data || data.length === 0) {
        throw new Error(`Certificat introuvable pour le fournisseur ${supplierID}`);
    }

    const cert: Certificate = JSON.parse(Buffer.from(data).toString('utf8'));

    // Sécurité : Si déjà révoqué, on ne fait plus rien
    if (cert.Status === 'REVOKED') {
        return JSON.stringify(cert);
    }

    // 1. On incrémente le nombre d'anomalies détectées (pour l'historique et Kibana)
    if (cert.WarningCount === undefined || cert.WarningCount === null) {
        cert.WarningCount = 0;
    }
    cert.WarningCount += 1;
    cert.LastUpdate = this.getTimestamp(ctx);

    // 2. On applique la baisse de score suite à l'anomalie
    let currentScore = cert.QualityScore !== undefined ? cert.QualityScore : 10.0;
    currentScore = currentScore - 1.0; // 
    if (currentScore < 0) currentScore = 0;

    // Arrondir proprement à 1 décimale
    cert.QualityScore = Math.round(currentScore * 10) / 10;

    // 3. 🚨 LA LOGIQUE EXACTE : Vérification du Score Global uniquement
    if (cert.QualityScore < 7.0) {
        cert.Status = 'REVOKED';
        cert.RevocationReason = `Révocation automatique SOAR — Score global insuffisant (${cert.QualityScore}/10 < 7.0) suite à l'anomalie (Alerte ID: ${alertID})`;
    } else {
        cert.Status = 'VALID';
        cert.RevocationReason = `Avertissement SecOps appliqué [${cert.WarningCount} anomalie(s)] — Score actuel: ${cert.QualityScore}/10 (Alerte ID: ${alertID})`;
    }

    // 4. Sauvegarde dans la Blockchain
    await ctx.stub.putState(`CERT_${supplierID}`, Buffer.from(JSON.stringify(cert)));
    return JSON.stringify(cert);
}
  @Transaction()
  public async RevokeCertificate(ctx:Context,supplierID:string,reason:string):Promise<string>{
    const data=await ctx.stub.getState(`CERT_${supplierID}`);
    if(!data||data.length===0) throw new Error(`Certificat introuvable pour ${supplierID}`);
    const cert:Certificate=JSON.parse(Buffer.from(data).toString('utf8'));
    cert.Status='REVOKED'; cert.RevocationReason=reason; cert.LastUpdate=this.getTimestamp(ctx);
    await ctx.stub.putState(`CERT_${supplierID}`,Buffer.from(JSON.stringify(cert)));
    return JSON.stringify(cert);
  }
  @Transaction()
  public async UpdateSupplierScore(ctx:Context,supplierID:string,defectRate:string,deliveryOnTimeRate:string):Promise<string>{
    const data=await ctx.stub.getState(`CERT_${supplierID}`);
    if(!data||data.length===0) throw new Error(`Certificat introuvable pour ${supplierID}`);
    const cert:Certificate=JSON.parse(Buffer.from(data).toString('utf8'));
    const d=parseFloat(defectRate); const del=parseFloat(deliveryOnTimeRate);
    cert.DefectRate=d; cert.DeliveryOnTimeRate=del;
    cert.QualityScore=this.calculateQualityScore(d,del,cert.QualityScore);
    cert.LastUpdate=this.getTimestamp(ctx);
    if(cert.QualityScore>=7.0&&d<=5){cert.Status='VALID';cert.RevocationReason='';}
    else if(d>5){cert.Status='SUSPENDED';cert.RevocationReason=`Défaut élevé:${d}%`;}
    else{cert.Status='REVOKED';cert.RevocationReason=`Score:${cert.QualityScore}<7.0`;}
    await ctx.stub.putState(`CERT_${supplierID}`,Buffer.from(JSON.stringify(cert)));
    return JSON.stringify(cert);
  }
  @Transaction(false)
  public async VerifyCertificate(ctx:Context,supplierID:string):Promise<string>{
    const data=await ctx.stub.getState(`CERT_${supplierID}`);
    if(!data||data.length===0) return JSON.stringify({isValid:false,reason:`Aucun certificat pour ${supplierID}`});
    const cert:Certificate=JSON.parse(Buffer.from(data).toString('utf8'));
    const now=new Date(this.getTimestamp(ctx)); const expiry=new Date(cert.ExpiryDate);
    if(cert.Status!=='VALID') return JSON.stringify({isValid:false,reason:`Certificat ${cert.Status}`,cert});
    if(now>expiry) return JSON.stringify({isValid:false,reason:`Expiré le ${cert.ExpiryDate}`,cert});
    if(cert.QualityScore<7.0) return JSON.stringify({isValid:false,reason:`Score ${cert.QualityScore}<7.0`,cert});
    return JSON.stringify({isValid:true,reason:'Certificat valide',cert});
  }
  @Transaction(false)
  public async GetCertificate(ctx:Context,supplierID:string):Promise<string>{
    const data=await ctx.stub.getState(`CERT_${supplierID}`);
    if(!data||data.length===0) throw new Error(`Certificat introuvable pour ${supplierID}`);
    return Buffer.from(data).toString('utf8');
  }

  // ── Rôles (Phase 3 ) ────────────────────────────


// (Permettre à l'Admin d'assigner des rôles sans certificat préalable,
//  et faire un upsert au lieu de bloquer si le rôle existe déjà)
@Transaction()
public async AssignRole(ctx: Context, supplierID: string, role: string): Promise<string> {
  if (!this.VALID_ROLES.includes(role)) throw new Error(`Rôle invalide: ${role}`);

  const actorFullID = ctx.clientIdentity.getID();
  const callerID    = this.extractSupplierID(actorFullID);

  // Vérifier que l'appelant est Admin
  const iterator    = await ctx.stub.getStateByRange('ROLE_', 'ROLE_~');
  let adminCount    = 0;
  let res           = await iterator.next();
  while (!res.done) {
    const r: RoleRecord = JSON.parse(res.value.value.toString());
    if (r.Role === 'Admin' && r.IsActive) adminCount++;
    res = await iterator.next();
  }
  await iterator.close();

  if (adminCount === 0) {
    // Bootstrap : premier appel, s'auto-assigner Admin
    if (role !== 'Admin')
      throw new Error('Bootstrap: premier rôle doit être Admin');
  } else {
    const callerData = await ctx.stub.getState(`ROLE_${callerID}`);
    if (!callerData || callerData.length === 0)
      throw new Error(`Accès refusé — ${callerID} n'a aucun rôle`);
    const callerRole: RoleRecord = JSON.parse(Buffer.from(callerData).toString('utf8'));
    if (!callerRole.IsActive || callerRole.Role !== 'Admin')
      throw new Error(`Accès refusé — ${callerID} n'est pas Admin`);
  }

  const now = this.getTimestamp(ctx);

  // UPSERT : si rôle existant (même révoqué), on le met à jour
  const existing = await ctx.stub.getState(`ROLE_${supplierID}`);
  const roleRecord = (existing && existing.length > 0)
    ? JSON.parse(Buffer.from(existing).toString('utf8')) as RoleRecord
    : new RoleRecord();

  roleRecord.SupplierID   = supplierID;
  roleRecord.Role         = role;
  roleRecord.AssignedBy   = callerID;
  roleRecord.AssignedDate = now;
  roleRecord.IsActive     = true;
  roleRecord.RevokedReason = '';

  await ctx.stub.putState(`ROLE_${supplierID}`, Buffer.from(JSON.stringify(roleRecord)));
  return JSON.stringify(roleRecord);
}


  @Transaction()
  public async RevokeRole(ctx:Context,supplierID:string,reason:string):Promise<string>{
    const actorFullID=ctx.clientIdentity.getID();
    const callerID=this.extractSupplierID(actorFullID);
    const callerData=await ctx.stub.getState(`ROLE_${callerID}`);
    if(!callerData||callerData.length===0) throw new Error(`${callerID} n'a aucun rôle`);
    const callerRole:RoleRecord=JSON.parse(Buffer.from(callerData).toString('utf8'));
    if(!callerRole.IsActive||callerRole.Role!=='Admin') throw new Error('Seul Admin peut révoquer');
    const roleData=await ctx.stub.getState(`ROLE_${supplierID}`);
    if(!roleData||roleData.length===0) throw new Error(`Aucun rôle pour ${supplierID}`);
    const roleRecord:RoleRecord=JSON.parse(Buffer.from(roleData).toString('utf8'));
    if(!roleRecord.IsActive) throw new Error(`Rôle de ${supplierID} déjà révoqué`);
    roleRecord.IsActive=false; roleRecord.RevokedReason=reason;
    await ctx.stub.putState(`ROLE_${supplierID}`,Buffer.from(JSON.stringify(roleRecord)));
    return JSON.stringify(roleRecord);
  }
  @Transaction(false)
  public async GetRole(ctx:Context,supplierID:string):Promise<string>{
    const data=await ctx.stub.getState(`ROLE_${supplierID}`);
    if(!data||data.length===0) throw new Error(`Aucun rôle pour ${supplierID}`);
    return Buffer.from(data).toString('utf8');
  }

  // ── Validation + Historique  ──────────
  @Transaction(false)
  public async ValidateFullChain(ctx:Context,lastRecordID:string):Promise<string>{
    const report=new ValidationReport(); report.Details=[]; report.AnomaliesDetected=[];
    let currentID=lastRecordID; let steps=0;
    while(currentID!==''){
      steps++;
      const record=await this.getRecord(ctx,currentID);
      const expectedHash=this.calculateHash(record);
      if(expectedHash!==record.Hash){report.AnomaliesDetected.push(`HASH INVALIDE: ${record.ID}`);report.Details.push(`Erreur ${record.Type} [${record.ID}]`);}
      else{report.Details.push(`OK ${record.Type} [${record.ID}]`);}
      if(record.PreviousHash!==''){
        const it=await ctx.stub.getStateByRange('','');
        let found=false; let r=await it.next();
        while(!r.done){const prev=JSON.parse(r.value.value.toString()) as TraceRecord;if(prev.Hash===record.PreviousHash){found=true;currentID=prev.ID;break;}r=await it.next();}
        await it.close();
        if(!found){report.AnomaliesDetected.push(`LIEN BRISÉ: ${record.ID}`);currentID='';}
      }else{report.Details.push(`Genèse: ${record.ID}`);currentID='';}
    }
    report.ChainLength=steps; report.IsValid=report.AnomaliesDetected.length===0;
    report.IntegrityScore=report.IsValid?100:Math.max(0,100-(report.AnomaliesDetected.length*20));
    return JSON.stringify(report,null,2);
  }
  @Transaction(false)
  public async GetTraceHistory(ctx:Context,productID:string):Promise<string>{
    const iterator=await ctx.stub.getStateByRange('','');
    const results:TraceRecord[]=[]; let res=await iterator.next();
    while(!res.done){const r=JSON.parse(res.value.value.toString()) as TraceRecord;if(r.ProductID===productID)results.push(r);res=await iterator.next();}
    await iterator.close();
    results.sort((a,b)=>a.Timestamp.localeCompare(b.Timestamp));
    return JSON.stringify(results,null,2);
  }
  @Transaction(false)
  public async ReadRecord(ctx:Context,id:string):Promise<string>{
    const data=await ctx.stub.getState(id);
    if(!data||data.length===0) throw new Error(`Enregistrement "${id}" introuvable`);
    return Buffer.from(data).toString('utf8');
  }
}
