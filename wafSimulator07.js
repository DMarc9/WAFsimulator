const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');

// Caminho arquivo CSV e arquivo de log
const csvFilePath = path.join(__dirname, 'test-dataset.csv');
const logFilePath = path.join(__dirname, 'firewall-log.txt');

// Listas permissão e bloqueio
const allowList = ['42.143.155.128', '50.97.88.31', '167.156.227.203', '151.104.73.27', '144.79.40.8'];
const blockList = new Map(); // Lista de bloqueio com timestamps

// Regras diferentes ZoneNames
const rules = {
    'infinitepay.io': [
        /' OR 1=1--/i,
        /union.*select.*from/i
    ],
    'otherzone.io': [
        // Outras regras diferentes zones
    ]
};

// Function registro actions no log
const logAction = (message) => {
    fs.appendFile(logFilePath, `${new Date().toISOString()} - ${message}\n`, (err) => {
        if (err) {
            console.error('Erro ao registrar no log:', err);
        }
    });
};

// Function add IP à lista de bloqueios
const addToBlockList = (ip) => {
    const blockTimestamp = Date.now();
    blockList.set(ip, blockTimestamp);
    logAction(`IP ${ip} adicionado à lista de bloqueios.`);
};

// Function limpar lista de bloqueios após 12 horas
const cleanUpBlockList = () => {
    const currentTime = Date.now();
    for (const [ip, timestamp] of blockList) {
        if (currentTime - timestamp > 12 * 60 * 60 * 1000) { // 12 horas em milissegundos
            blockList.delete(ip);
            logAction(`IP ${ip} removido da lista de bloqueios após 12 horas.`);
        }
    }
};

// Function filtrar tráfego com base nas listas de IP
const filterTraffic = (ip) => {
    cleanUpBlockList(); // Limpar lista de bloqueios antes de verificar
    if (allowList.includes(ip)) {
        return 'allowed';
    } else if (blockList.has(ip)) {
        return 'blocked';
    } else {
        return 'unknown';
    }
};

// Function verificar SQL Injection e adicionar à lista de bloqueio
const isSQLInjection = (zoneName, path) => {
    const zoneRules = rules[zoneName] || [];
    if (zoneRules.some(rule => rule.test(path))) {
        addToBlockList(row['ClientIP']);
        return true;
    }
    return false;
};

// Function para remover manualmente IPs da lista de bloqueios
const removeFromBlockList = (ip) => {
    if (blockList.has(ip)) {
        blockList.delete(ip);
        logAction(`IP ${ip} removido manualmente da lista de bloqueios.`);
    } else {
        logAction(`Tentativa de remoção de IP ${ip} que não está na lista de bloqueios.`);
    }
};

// Function processar o CSV
const processCSV = (csvFilePath) => {
    fs.access(csvFilePath, fs.constants.F_OK, (err) => {
        if (err) {
            console.error('Arquivo CSV não encontrado:', csvFilePath);
            return;
        }

        fs.createReadStream(csvFilePath)
            .pipe(csv())
            .on('headers', (headers) => {
                console.log('Headers:', headers); // Exibir cabeçalhos das colunas
            })
            .on('data', (row) => {
                console.log('Row Data:', row); // Added para verificar conteúdo da linha
                const ip = row['ClientIP'];
                const zoneName = row['ZoneName'];
                const requestPath = row['ClientRequestPath'];
                
                const ipStatus = filterTraffic(ip);
                console.log(`IP: ${ip} - Status: ${ipStatus}`);
                logAction(`IP: ${ip} - Status: ${ipStatus}`);

                if (zoneName && requestPath) {
                    const isBlocked = isSQLInjection(zoneName, requestPath);
                    if (isBlocked) {
                        console.log(`Bloqueado: ${requestPath} - SQL Injection detectado`);
                        logAction(`Bloqueado: ${requestPath} - SQL Injection detectado`);
                    } else {
                        console.log(`Permitido: ${requestPath}`);
                        logAction(`Permitido: ${requestPath}`);
                    }
                } else {
                    console.log('Dados insuficientes na linha:', row);
                    logAction('Dados insuficientes na linha:' + JSON.stringify(row));
                }
            })
            .on('end', () => {
                console.log('Arquivo CSV processado com sucesso.');
                logAction('Arquivo CSV processado com sucesso.');
                console.log('Lista de bloqueios atualizada:', Array.from(blockList.keys()));
                logAction('Lista de bloqueios atualizada: ' + Array.from(blockList.keys()).join(', '));
            });
    });
};

// Function processar o CSV
processCSV(csvFilePath);
