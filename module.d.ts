declare module 'dguard' {
    export interface DGuardOptions {
        /**
         * use local In-Memory KMS
         * @default false
         */
        local?: boolean;
    }

    /**
     * DGuard를 초기화합니다.
     * @param options
     */
    export function init(options?: { local: boolean }): void;

    /**
     * value를 암호화합니다.
     * @param tableName
     * @param columnName
     * @param value
     * @throws {Error} KMS 오류로 암호화에 실패했을 때
     */
    export function encrypt(tableName: string, columnName: string, value: string): Promise<string>;

    /**
     * value를 복호화합니다.
     * @param tableName
     * @param columnName
     * @param value
     * @throws {Error} value 값이 잘못됨
     * @throws {Error} KMS 오류로 복호화에 실패
     */
    export function decrypt(tableName: string, columnName: string, value: string): Promise<string>;

    /**
     * value로 hash를 생성합니다.
     * @param tableName
     * @param columnName
     * @param value
     * @throws {Error} KMS 오류로 hash 생성에 실패
     */
    export function hash(tableName: string, columnName: string, value: string): Promise<string>;

    /**
     * DGuard를 종료합니다.
     */
    export function close(): void;
}