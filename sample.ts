import * as dguard from 'dguard';

console.log(dguard.encrypt("CRYPTO", "ENC", "1111111111118"));
console.log(dguard.decrypt("CRYPTO", "ENC", "3fNzyEOkA412Pjuvu13GgQ=="));
console.log(dguard.hash("CRYPTO", "PWD", "1111111111118"));
