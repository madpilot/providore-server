export interface Firmware {
  type: string;
  version: string;
  config: string;
  file: string;
  next?: string;
}

export interface Device {
  secretKey: string;
  firmware: Array<Firmware>;
}

export type Devices = Record<string, Device>;

export interface FirmwareParams {
  version?: string;
}
