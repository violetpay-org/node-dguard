const dguard = require('./index');

dguard.init({ local: true });

async function bootstrap() {
    const enc = await dguard.encrypt("CRYPTO", "ENC", "1111111111118")
    console.log("enc:", enc)

    console.log("dec:", await dguard.decrypt("CRYPTO", "ENC", enc))

    console.log("hash:", await dguard.hash("CRYPTO", "PWD", "1111111111118"))
}

bootstrap();
