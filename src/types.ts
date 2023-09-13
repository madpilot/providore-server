export interface Firmware {
  type: string;
  version: string;
  config: string;
  file: string;
  next?: string;
}

export interface Certificate {
  extensions?: "server_cert" | "user_cert";
  days?: number;
}

export interface Device {
  secretKey: string;
  certificate?: Certificate;
  firmware: Array<Firmware>;
}

export type Devices = Record<string, Device>;

export interface FirmwareParams {
  version?: string;
}
