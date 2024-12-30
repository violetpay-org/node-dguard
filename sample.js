
const addon_path = process.env.EAP_HOME;
const addon = require(addon_path + '/node-c-addon/build/Release/addon');

console.log(addon.Encrypt("CRYPTO", "ENC", "1111111111118"));
console.log(addon.Decrypt("CRYPTO", "ENC", "3fNzyEOkA412Pjuvu13GgQ=="));
console.log(addon.Hash("CRYPTO", "PWD", "1111111111118"));
