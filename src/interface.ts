import fs from 'fs';
import path from 'path';
import NodeRSA from 'node-rsa';
const relayerUtils = require('@zk-email/relayer-utils');
const {
  generateJWTAuthenticatorInputs
} =require('@zk-email/jwt-tx-builder-helpers/src/input-generators');

import { base64ToBigInt } from '@zk-email/jwt-tx-builder-helpers/src/utils';
import { toCircomBigIntBytes, Uint8ArrayToCharArray } from '@zk-email/helpers';



export async function generateCircuitInputs(
  message: string,
  privateKey: string
) {
  // validateInputs(rawJWT, publicKey);
  // const [headerString, payloadString, signatureString] = splitJWT(rawJWT);
  // await verifyJWTSignature(rawJWT, publicKey);

  // const periodIndex = rawJWT.indexOf('.');
  // const [messagePadded, messagePaddedLen] = prepareMessage(headerString, payloadString, params);

  const key = new NodeRSA(privateKey);
  // const messagePadded = '0xwerwerwer' // pre-computed: check circuits for more details
  // cost messagePadded = 'asdddddddd';
  const messagePadded = Buffer.from(`${message}`);
  const signature = key.sign(Buffer.from(`${message}`), 'base64', 'utf8');
  const publicKey = {
    n: key.exportKey('components').n.toString('base64'),
    e: key.exportKey('components').e,
  };
  return {
    message: Uint8ArrayToCharArray(messagePadded),
    pubkey: toCircomBigIntBytes(base64ToBigInt(publicKey.n)),
    signature: toCircomBigIntBytes(base64ToBigInt(signature))
  };
}

async function generateTestData() {
  const testCases = [
    {
      message: '0xwerwerwer',
      server_key: '-----BEGIN RSA PRIVATE KEY-----\n' +
                  'MIIEpAIBAAKCAQEA1TBbdWgfopHuS973DmCjilZCessxQrpZ6A/Ms76txS7pkC/X\n'+
                  't+ev66K8XjdaLZk27s296azfPBgxn3kjoHVg1QXyHmbQsueoT8zx2o9JfjuIawSh\n'+
                  'D79V11WP7weFPchsa7zeMD9zmAuGvCmAk1saebJjhIwOLRtSSYxLnaZsSy9Vo1RQ\n'+
                  'z9q/vLYj4ogv72ZDrXx/gTt4EytoI1FuuZs7nW8h0VR3KftzpbCWi0zY7xzuQK8c\n'+
                  'WvvxVDsylH77mcAMl1oshL/fWztQVdaDtGw2BXejEOX7OD3DhjIkXSd6zOeeO+aI\n'+
                  '6WlMd8AXfS/VwfDuy6GIGqvxxyETtbCT/cfJgwIDAQABAoIBAQCEjFNg9QMuRcM+\n'+
                  'YvuCce1cdnNQ+4K+NTTvBtvEKdrKzXckUcqyqheDzyOFBK9JyIgSA9N/NR96sqQv\n'+
                  'vda7zh8Nc2vtIQnDIitQqmD4/bu5A3S27SLispjBkI40FJ3wIuveNIiEwP6y2v/D\n'+
                  'f55UgAE/Bv2/DIFH5EPOPK9K7o1IVJw8pCxw+5qL2+gLafq0eOkf+5TZylLHvjPl\n'+
                  'Uc4QPauZlhFyfNDqdomf/+yC0U3ai1RogAOEsxd6fHqwykgg706o6hF5qPk6jd2r\n'+
                  'Hroc1o2HCINQsZNKStcCXhDcVyG/UU9NtvIdsaUGKkUpUSUWw13loUj2ni5/r8/1\n'+
                  'ZpuDUndZAoGBAO7ZvceY9LWolVUd0BYYlclIBEjbMuC/+DapEG2/j4TIbxNHMcEe\n'+
                  '2DU+I8ATW7toV8EoFahDWy3ByNVpratee8E+xEaS7exNHknN3Vbrt58mXgksTrxm\n'+
                  'NwjVxMokzWQb218P1Q15VIGHn/hnoh55Kqu/QxkqldWEqTlBryNhS3N/AoGBAOR+\n'+
                  '70wLnfLces0ga72YFzEtxO6llh4Ezg6eNia3adX8drlC63vgdOYq0x5pu0sz0adi\n'+
                  'EPsvIKv25PPUjoXYsfk0exGaxvSY7BAxqNZDBMEBdBHFcsMT59KpnCgp3Ta2J8Ey\n'+
                  'ufJgmI+bCy99p8/GUxI+mp4b1oXSaJN7ldMWF9v9AoGBAIY0ooX8U8OergndboZ7\n'+
                  '2e33ITEuuS+/reBIrop8EFAzrvXOEw7IHgQMnlnWhryOrIBD3adl8V2MfSQs9QBN\n'+
                  'Xov+kJp3BGi6DEK8AZpNaCdsj3noA3WomVPFiYVrmFyfqmuHodaoTetaIXCaCmXE\n'+
                  '/0zxcuo5G2eV2t/pIFdo29RRAoGAWhzNVtpGAl99dqRQmUb/7n80aUGYgGI4uX8f\n'+
                  'sAkpjiCw2cNQh1wv/g3pkNb17GSVTEPampUtd2Q5SwgK5TJejf9qgbjeudwNTR2o\n'+
                  'jkeD+nIOSmvqJJEXHfeSBCzudwNDjmfo+XOq9weYU7RkmAaJAGr8I1qrMb+XSoK0\n'+
                  'xbiy1CkCgYAXPkoSuXxw8r3y4hTaojHMIxd8oczGUhESxlCUOdh2FBsL8nmcsv3k\n'+
                  '7XpBlI98gmbeHX8OohrZ6sISX1O5r8bH/ABSMYom7XhhsqmG27PoGRJ4r0ly8ep6\n'+
                  '534xC8bWl7PfHlxEZzuhpWc0cV0MgCm15JaQdcY2yD9fkTU/43XtHA==\n' +
                  '-----END RSA PRIVATE KEY-----'
    },
    {
      message: '0xwerwerwer',
      private_key: '-----BEGIN RSA PRIVATE KEY-----\n'+
                  'MIIEpAIBAAKCAQEAj02Q65/uoi9yq8hvzi1qBBWFQ//H3+iXZmSmmFjXXGbU2K8o\n'+
                  'TZPCAnmSr28F/vBlvt3iBv1GXq0GWbaaITnmq3yMc6fT3BPvElDBNt4MXpY9BcSx\n'+
                  'UeX4yBl808LGu5BAzwv9HZcYm4MGi3y/MMTtQZvXyGePPgAv7WylHux/t21Cxptz\n'+
                  'WnMWAbfb3zVE609N14eDbF3T+1Z6JlI/N7IKbKl+/AxxD6+dJuMsFjTVr6M/OYSU\n'+
                  'FgLSfdwePApoty758NPm1wLnz2tJuYFIXhDre8LeEWYHbkBRMeSzkQd9SsvTBMhs\n'+
                  'IC1HRCWXPBrFg3PNe30nCsuhvvx/ueixeJI82wIDAQABAoIBAEec/LIzn36fdY/R\n'+
                  'P8ZqPZPC6XE87ra/toFuBS8XHrDHltCeX+a803SHKr3PHtDzc/U5Tw4tHjCMCSNm\n'+
                  'NIosNFE4kbvuf9p4f73Ia3Yu60GNlPs/+1kxMu1Uh2QP716mTSzrEdfqvVph1TB5\n'+
                  '69XEY8iox+IXlqbmUw00gSP+Diksil9VhntTpIQNzncrRB6COhHgrioRX0zVy+4F\n'+
                  'nVz+YWveRYiOHNO3tUGHDxYpAucGTpdt7Hu83bgFzsoGZ4ezavZ2ZzM8uoBE6np3\n'+
                  'k7lg/lOZxPRTWrtH1DYGhEeaHLp0KdW6pYJqNX8MucJncgUgVAYeTcuPrL/DfeCJ\n'+
                  'Mq9Qh6ECgYEAx0g/mChBqK/OVXv7+Z6WEEU/aVJk3xssQ1YZqxP8bgUKKff2xJSP\n'+
                  'i9/g2umDtEjTXDLfrjUxVU7cirIUeB4qZhNO3dGwXpyxVvB+EPXuWsKXcvoMnL0T\n'+
                  'A4nOP09SAXyC5/qmYmyD10jiiygf3jmxJWO3abDGZMdg698FuBTV03ECgYEAuBao\n'+
                  'Sbcq1sKF1hvcWmEtQ9LnLyVFYkpIHUEwfkuXa5CjZMCFaI5xkCdjfNoN9ZrsY5Q+\n'+
                  'rHnfHhSXBAc8MNFWKV+dlPSgdhIwyxL47ahtq0mCZYhr0QV/YZMGM3zejpmmJNgG\n'+
                  'a46JEdw+e9qQ3ltuTpb9+v56I99l4XEix2wTFwsCgYEAupu7+UaRHV3rT/821+uZ\n'+
                  'yAigNYbTMFxomXFxvdKMSZXsi5pH+JLIzIlLLJMIInUjfq2g6aej16duO25AXq6Y\n'+
                  's1cXPf3SMvZ11dyDoGw608BuQ1tFHiyrNl//wycKupuWlZYP4hCNcLYudXKQTO8n\n'+
                  'I8T5hj3juZE+AAGqgFL6W/ECgYEAt3K0v8kNorh0oPpgq5xdfFJG2d+ddiaqGKUn\n'+
                  'CySPP70CZtvH1nrkxo/J/9hYwuFhIpbPohdM9e/00inXnJpv74j+QztIUIEuKKC+\n'+
                  'ei83ItN9Y2sAbmq5FuZp7pNIQfjx7ZNtSm/fPnIpvkj/xuZ8VUr4zNAdrXPpVjDl\n'+
                  'RK/5kiMCgYB/RICNuOimRGdGHd1FxbJzmVQ6GLZQ7DZKeMPYjHyI5KVk/GHhfQol\n'+
                  'TG5Aq+3vz6VYP7oT/39lVl3noTCLZ+Tfzk4YFb2FolsBGBMRc4ht7ZcqbqMb4JXO\n'+
                  'U7Kg2+hxlqMyikiQgg1remrJhTWLnwN9ROdMJE7nunWxR8xaQyb50Q==\n'+
                  '-----END RSA PRIVATE KEY-----'
    },
    {
      message: '0xwerwerwer',
      server_key: '-----BEGIN RSA PRIVATE KEY-----\n' +
                  'MIIEpAIBAAKCAQEA1TBbdWgfopHuS973DmCjilZCessxQrpZ6A/Ms76txS7pkC/X\n'+
                  't+ev66K8XjdaLZk27s296azfPBgxn3kjoHVg1QXyHmbQsueoT8zx2o9JfjuIawSh\n'+
                  'D79V11WP7weFPchsa7zeMD9zmAuGvCmAk1saebJjhIwOLRtSSYxLnaZsSy9Vo1RQ\n'+
                  'z9q/vLYj4ogv72ZDrXx/gTt4EytoI1FuuZs7nW8h0VR3KftzpbCWi0zY7xzuQK8c\n'+
                  'WvvxVDsylH77mcAMl1oshL/fWztQVdaDtGw2BXejEOX7OD3DhjIkXSd6zOeeO+aI\n'+
                  '6WlMd8AXfS/VwfDuy6GIGqvxxyETtbCT/cfJgwIDAQABAoIBAQCEjFNg9QMuRcM+\n'+
                  'YvuCce1cdnNQ+4K+NTTvBtvEKdrKzXckUcqyqheDzyOFBK9JyIgSA9N/NR96sqQv\n'+
                  'vda7zh8Nc2vtIQnDIitQqmD4/bu5A3S27SLispjBkI40FJ3wIuveNIiEwP6y2v/D\n'+
                  'f55UgAE/Bv2/DIFH5EPOPK9K7o1IVJw8pCxw+5qL2+gLafq0eOkf+5TZylLHvjPl\n'+
                  'Uc4QPauZlhFyfNDqdomf/+yC0U3ai1RogAOEsxd6fHqwykgg706o6hF5qPk6jd2r\n'+
                  'Hroc1o2HCINQsZNKStcCXhDcVyG/UU9NtvIdsaUGKkUpUSUWw13loUj2ni5/r8/1\n'+
                  'ZpuDUndZAoGBAO7ZvceY9LWolVUd0BYYlclIBEjbMuC/+DapEG2/j4TIbxNHMcEe\n'+
                  '2DU+I8ATW7toV8EoFahDWy3ByNVpratee8E+xEaS7exNHknN3Vbrt58mXgksTrxm\n'+
                  'NwjVxMokzWQb218P1Q15VIGHn/hnoh55Kqu/QxkqldWEqTlBryNhS3N/AoGBAOR+\n'+
                  '70wLnfLces0ga72YFzEtxO6llh4Ezg6eNia3adX8drlC63vgdOYq0x5pu0sz0adi\n'+
                  'EPsvIKv25PPUjoXYsfk0exGaxvSY7BAxqNZDBMEBdBHFcsMT59KpnCgp3Ta2J8Ey\n'+
                  'ufJgmI+bCy99p8/GUxI+mp4b1oXSaJN7ldMWF9v9AoGBAIY0ooX8U8OergndboZ7\n'+
                  '2e33ITEuuS+/reBIrop8EFAzrvXOEw7IHgQMnlnWhryOrIBD3adl8V2MfSQs9QBN\n'+
                  'Xov+kJp3BGi6DEK8AZpNaCdsj3noA3WomVPFiYVrmFyfqmuHodaoTetaIXCaCmXE\n'+
                  '/0zxcuo5G2eV2t/pIFdo29RRAoGAWhzNVtpGAl99dqRQmUb/7n80aUGYgGI4uX8f\n'+
                  'sAkpjiCw2cNQh1wv/g3pkNb17GSVTEPampUtd2Q5SwgK5TJejf9qgbjeudwNTR2o\n'+
                  'jkeD+nIOSmvqJJEXHfeSBCzudwNDjmfo+XOq9weYU7RkmAaJAGr8I1qrMb+XSoK0\n'+
                  'xbiy1CkCgYAXPkoSuXxw8r3y4hTaojHMIxd8oczGUhESxlCUOdh2FBsL8nmcsv3k\n'+
                  '7XpBlI98gmbeHX8OohrZ6sISX1O5r8bH/ABSMYom7XhhsqmG27PoGRJ4r0ly8ep6\n'+
                  '534xC8bWl7PfHlxEZzuhpWc0cV0MgCm15JaQdcY2yD9fkTU/43XtHA==\n' +
                  '-----END RSA PRIVATE KEY-----'
    },
    {
      message: '0xwerwerwer',
      private_key: '-----BEGIN RSA PRIVATE KEY-----\n'+
                  'MIIEpAIBAAKCAQEAj02Q65/uoi9yq8hvzi1qBBWFQ//H3+iXZmSmmFjXXGbU2K8o\n'+
                  'TZPCAnmSr28F/vBlvt3iBv1GXq0GWbaaITnmq3yMc6fT3BPvElDBNt4MXpY9BcSx\n'+
                  'UeX4yBl808LGu5BAzwv9HZcYm4MGi3y/MMTtQZvXyGePPgAv7WylHux/t21Cxptz\n'+
                  'WnMWAbfb3zVE609N14eDbF3T+1Z6JlI/N7IKbKl+/AxxD6+dJuMsFjTVr6M/OYSU\n'+
                  'FgLSfdwePApoty758NPm1wLnz2tJuYFIXhDre8LeEWYHbkBRMeSzkQd9SsvTBMhs\n'+
                  'IC1HRCWXPBrFg3PNe30nCsuhvvx/ueixeJI82wIDAQABAoIBAEec/LIzn36fdY/R\n'+
                  'P8ZqPZPC6XE87ra/toFuBS8XHrDHltCeX+a803SHKr3PHtDzc/U5Tw4tHjCMCSNm\n'+
                  'NIosNFE4kbvuf9p4f73Ia3Yu60GNlPs/+1kxMu1Uh2QP716mTSzrEdfqvVph1TB5\n'+
                  '69XEY8iox+IXlqbmUw00gSP+Diksil9VhntTpIQNzncrRB6COhHgrioRX0zVy+4F\n'+
                  'nVz+YWveRYiOHNO3tUGHDxYpAucGTpdt7Hu83bgFzsoGZ4ezavZ2ZzM8uoBE6np3\n'+
                  'k7lg/lOZxPRTWrtH1DYGhEeaHLp0KdW6pYJqNX8MucJncgUgVAYeTcuPrL/DfeCJ\n'+
                  'Mq9Qh6ECgYEAx0g/mChBqK/OVXv7+Z6WEEU/aVJk3xssQ1YZqxP8bgUKKff2xJSP\n'+
                  'i9/g2umDtEjTXDLfrjUxVU7cirIUeB4qZhNO3dGwXpyxVvB+EPXuWsKXcvoMnL0T\n'+
                  'A4nOP09SAXyC5/qmYmyD10jiiygf3jmxJWO3abDGZMdg698FuBTV03ECgYEAuBao\n'+
                  'Sbcq1sKF1hvcWmEtQ9LnLyVFYkpIHUEwfkuXa5CjZMCFaI5xkCdjfNoN9ZrsY5Q+\n'+
                  'rHnfHhSXBAc8MNFWKV+dlPSgdhIwyxL47ahtq0mCZYhr0QV/YZMGM3zejpmmJNgG\n'+
                  'a46JEdw+e9qQ3ltuTpb9+v56I99l4XEix2wTFwsCgYEAupu7+UaRHV3rT/821+uZ\n'+
                  'yAigNYbTMFxomXFxvdKMSZXsi5pH+JLIzIlLLJMIInUjfq2g6aej16duO25AXq6Y\n'+
                  's1cXPf3SMvZ11dyDoGw608BuQ1tFHiyrNl//wycKupuWlZYP4hCNcLYudXKQTO8n\n'+
                  'I8T5hj3juZE+AAGqgFL6W/ECgYEAt3K0v8kNorh0oPpgq5xdfFJG2d+ddiaqGKUn\n'+
                  'CySPP70CZtvH1nrkxo/J/9hYwuFhIpbPohdM9e/00inXnJpv74j+QztIUIEuKKC+\n'+
                  'ei83ItN9Y2sAbmq5FuZp7pNIQfjx7ZNtSm/fPnIpvkj/xuZ8VUr4zNAdrXPpVjDl\n'+
                  'RK/5kiMCgYB/RICNuOimRGdGHd1FxbJzmVQ6GLZQ7DZKeMPYjHyI5KVk/GHhfQol\n'+
                  'TG5Aq+3vz6VYP7oT/39lVl3noTCLZ+Tfzk4YFb2FolsBGBMRc4ht7ZcqbqMb4JXO\n'+
                  'U7Kg2+hxlqMyikiQgg1remrJhTWLnwN9ROdMJE7nunWxR8xaQyb50Q==\n'+
                  '-----END RSA PRIVATE KEY-----'
    },
  ];

  // Create output directory if it doesn't exist
  const outputDir = path.join(__dirname, 'generated-inputs');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

   // Initialize result object with empty arrays
   const result = {
    sig: [],
    pk: [],
    l: [],
    msg: []
  };


  // Generate and collect data for each test case
  for (const testCase of testCases) {
    console.log('Generating test case...');
    
    // Generate JWT
    const { message, pubkey, signature } = generateCircuitInputs(testCase.message, testCase.private_key);


    // Add values to respective arrays
    for (const [key, value] of Object.entries(authInputs)) {
      result[key as keyof typeof result].push(value as never);
    }
  }

  // Save merged results
  fs.writeFileSync(
    path.join(outputDir, 'merged_results.json'),
    JSON.stringify(result, null, 2)
  );

  console.log(`Merged results saved in ${outputDir}/merged_results.json`);
}

// Run the generator
generateTestData().catch(console.error);