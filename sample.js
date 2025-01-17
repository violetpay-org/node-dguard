const dguard = require('./build/Release/dguard');

dguard.init();

dguard.encrypt("CRYPTO", "ENC", "1111111111118").then((res) => {
    console.log(res);
})

dguard.decrypt("CRYPTO", "ENC", "SPdPvcY2NnpMI2wdR8KgYw==").then((res) => {
    console.log(res);
})

dguard.hash("CRYPTO", "HASH", "1111111111118").then((res) => {
    console.log(res);
})