declare module 'dguard' {
    export interface DGuardOptions {
        /**
         * use local In-Memory KMS
         * @default false
         */
        local?: boolean;
    }

    export function init(options: { local: boolean }): void;
    export function encrypt(tableName: string, columnName: string, value: string): Promise<string>;
    export function decrypt(tableName: string, columnName: string, value: string): Promise<string>;
    export function hash(tableName: string, columnName: string): Promise<void>;
    export function close(): void;
}