export interface Certificate {
  extensions?: "server_cert" | "user_cert";
  days?: number;
}

export interface Device {
  secretKey: string;
  certificate?: Certificate;
}

export type Devices = Record<string, Device>;
