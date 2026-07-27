# Data Boundary

O checkout do RedLens e compartilhavel: codigo, testes, manifestos e os dois
workers do Kali ficam versionados aqui. Ele nao deve conter evidencias,
relatorios, caches de navegador, credenciais ou configuracao de uma maquina.

Dados operacionais ficam em `REDLENS_DATA_DIR`. Sem configuracao explicita, o
RedLens usa o diretorio de dados do sistema. Um `REDLENS_HOME` explicito cria
um ambiente portavel isolado com dados em `data/` sob esse home. Nesta maquina,
`redlens.toml` ignorado aponta para o volume ADATA.

O bootstrap cria `runs/`, `backups/` e o cache do CloakBrowser nesse diretorio.
Ele tambem copia o callback versionado para o workspace montado no container.
O workspace ativo deve conter apenas os workers versionados e esse callback
gerado; resultados de operacoes devem permanecer no diretorio de dados.

Material historico foi separado em um arquivo privado fora do checkout. Ele
nao deve ser compartilhado, versionado ou montado no container operacional.
