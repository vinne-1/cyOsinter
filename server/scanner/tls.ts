import tls from "tls";

export async function getCertificateInfo(hostname: string, port = 443): Promise<{
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  serialNumber: string;
  altNames: string[];
  protocol: string;
} | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { resolve(null); }, 8000);
    try {
      const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || "unknown";
          if (!cert || !cert.valid_from) {
            socket.destroy();
            clearTimeout(timer);
            resolve(null);
            return;
          }
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.floor((validTo.getTime() - now.getTime()) / 86400000);
          const altNames = cert.subjectaltname
            ? cert.subjectaltname.split(", ").map((s: string) => s.replace("DNS:", ""))
            : [];
          socket.destroy();
          clearTimeout(timer);
          resolve({
            subject: typeof cert.subject === "object" ? (cert.subject as any).CN || JSON.stringify(cert.subject) : String(cert.subject),
            issuer: typeof cert.issuer === "object" ? ((cert.issuer as any).O || (cert.issuer as any).CN || JSON.stringify(cert.issuer)) : String(cert.issuer),
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            serialNumber: cert.serialNumber || "",
            altNames,
            protocol,
          });
        } catch {
          socket.destroy();
          clearTimeout(timer);
          resolve(null);
        }
      });
      socket.on("error", () => { clearTimeout(timer); resolve(null); });
    } catch {
      clearTimeout(timer);
      resolve(null);
    }
  });
}
