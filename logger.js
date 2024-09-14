const { createLogger, format, transports } = require('winston');
const path = require('path');

const logger = createLogger({
    level: 'info',
    format: format.combine(
        format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss',
        }),
        format.errors({ stack: true }),
        format.splat(),
        format.json()
    ),
    defaultMeta: { service: 'firewall-service' },
    transports: [
        new transports.Console({
            format: format.combine(
                format.colorize(),
                format.simple()
            )
        }),
        new transports.File({ filename: path.join(__dirname, 'logs', 'error.log'), level: 'error' }),
        new transports.File({ filename: path.join(__dirname, 'logs', 'combined.log') }),
    ],
});

module.exports = logger;
