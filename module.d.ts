declare module 'dguard' {
    export function init(): void;
    export function encrypt(tableName: string, columnName: string, value: string): Promise<string>;
    export function decrypt(tableName: string, columnName: string, value: string): Promise<string>;
    export function hash(tableName: string, columnName: string): Promise<void>;
    export function close(): void;
}