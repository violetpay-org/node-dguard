declare module 'dguard' {
    export function encrypt(tableName: string, columnName: string, value: string): string;
    export function decrypt(tableName: string, columnName: string, value: string): string;
    export function hash(tableName: string, columnName: string, value: string): string;
}