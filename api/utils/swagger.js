// Configuração do Swagger UI para documentação da API
const swaggerUi = require('swagger-ui-express');

// Definição OpenAPI 3.0 da API BritofScan
const swaggerDocument = {
  openapi: '3.0.0',
  info: {
    title: 'BritofScan API',
    version: '1.0.0',
    description: 'Plataforma Educacional de Penetration Testing — API REST',
    contact: { name: 'BritofScan', email: 'suporte@britofscan.pt' },
  },
  servers: [
    { url: 'http://localhost:3001', description: 'Desenvolvimento' },
    { url: 'https://britofscan.vercel.app', description: 'Produção' },
  ],
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
    },
    schemas: {
      ScanRequest: {
        type: 'object',
        required: ['target', 'mode'],
        properties: {
          target: { type: 'string', example: 'https://example.com' },
          mode: { type: 'string', enum: ['stealth', 'standard', 'aggressive'], default: 'standard' },
          format: { type: 'string', enum: ['json', 'markdown', 'html'], default: 'json' },
        },
      },
      AuthRegister: {
        type: 'object',
        required: ['email', 'password', 'name'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 8 },
          name: { type: 'string' },
          role: { type: 'string', enum: ['estudante', 'professor', 'admin'], default: 'estudante' },
        },
      },
    },
  },
  paths: {
    '/api/health': {
      get: {
        summary: 'Health check',
        tags: ['Sistema'],
        responses: { 200: { description: 'API operacional' } },
      },
    },
    '/api/auth/register': {
      post: {
        summary: 'Registar nova conta',
        tags: ['Autenticação'],
        requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthRegister' } } } },
        responses: { 201: { description: 'Conta criada com sucesso' }, 400: { description: 'Dados inválidos' } },
      },
    },
    '/api/auth/login': {
      post: {
        summary: 'Iniciar sessão',
        tags: ['Autenticação'],
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  email: { type: 'string' },
                  password: { type: 'string' },
                },
              },
            },
          },
        },
        responses: { 200: { description: 'Token JWT retornado' }, 401: { description: 'Credenciais inválidas' } },
      },
    },
    '/api/auth/me': {
      get: {
        summary: 'Perfil do utilizador autenticado',
        tags: ['Autenticação'],
        security: [{ bearerAuth: [] }],
        responses: { 200: { description: 'Dados do perfil' }, 401: { description: 'Não autenticado' } },
      },
    },
    '/api/scan/start': {
      post: {
        summary: 'Iniciar um novo scan',
        tags: ['Scans'],
        security: [{ bearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/ScanRequest' } } } },
        responses: { 200: { description: 'Scan iniciado — resultados via WebSocket' }, 400: { description: 'Target inválido ou bloqueado' } },
      },
    },
    '/api/scan/history': {
      get: {
        summary: 'Histórico de scans',
        tags: ['Scans'],
        security: [{ bearerAuth: [] }],
        responses: { 200: { description: 'Lista de scans do utilizador' } },
      },
    },
    '/api/scan/{id}': {
      get: {
        summary: 'Obter scan por ID',
        tags: ['Scans'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { 200: { description: 'Dados do scan' }, 404: { description: 'Scan não encontrado' } },
      },
    },
    '/api/reports/{id}/export': {
      get: {
        summary: 'Exportar relatório',
        tags: ['Relatórios'],
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'format', in: 'query', schema: { type: 'string', enum: ['json', 'markdown', 'html'] } },
        ],
        responses: { 200: { description: 'Relatório no formato solicitado' } },
      },
    },
  },
};

module.exports = { swaggerUi, swaggerDocument };
