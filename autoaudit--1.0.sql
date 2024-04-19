\echo Use "CREATE EXTENSION autoaudit" to load this file. \quit
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------CREACION DEL ESQUEMA Y SUS PERMISOS--------------------------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE SCHEMA autoaudit;
REVOKE ALL ON SCHEMA autoaudit FROM PUBLIC;
GRANT ALL ON SCHEMA autoaudit TO CURRENT_USER;

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------CREACION DE LA TABLA DE AUDITORIA Y LA FUNCION PRINCIPAL-----------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE TABLE autoaudit.audit_log (
    id SERIAL PRIMARY KEY,
    operationType TEXT,
    tableName TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    username TEXT,
    clientIP TEXT,
    dataBefore JSONB,
    dataAfter JSONB
);

CREATE OR REPLACE FUNCTION autoaudit.audit_function()
RETURNS TRIGGER AS $$
BEGIN
    -- Determinar el tipo de operación
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO autoaudit.audit_log(operationType, tableName, username, clientIP, dataAfter)
        VALUES ('INSERT', TG_TABLE_NAME, current_user, inet_client_addr(), to_jsonb(NEW));
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO autoaudit.audit_log(operationType, tableName, username, clientIP, dataBefore, dataAfter)
        VALUES ('UPDATE', TG_TABLE_NAME, current_user, inet_client_addr(), to_jsonb(OLD), to_jsonb(NEW));
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO autoaudit.audit_log(operationType, tableName, username, clientIP, dataBefore)
        VALUES ('DELETE', TG_TABLE_NAME, current_user, inet_client_addr(), to_jsonb(OLD));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------GENERACION DE TRIGGERS PARA TABLAS EXISTENTES ANTES A LA IMPLEMENTACION--------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    tableName TEXT;
    schemaName TEXT;
BEGIN
    FOR tableName, schemaName IN SELECT table_name, table_schema FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema', 'autoaudit') AND table_type = 'BASE TABLE' LOOP
        EXECUTE 'CREATE TRIGGER audit_trigger_' || quote_ident(tableName) ||
                ' AFTER INSERT OR UPDATE OR DELETE ON ' || quote_ident(schemaName) || '.' || quote_ident(tableName) ||
                ' FOR EACH ROW EXECUTE PROCEDURE autoaudit.audit_function()';
    END LOOP;
END;
$$;
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------CREACION DE TRIGGER PARA TABLAS NUEVAS-----------------------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION autoaudit.create_audit_trigger()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'CREATE TABLE') THEN
        EXECUTE 'CREATE TRIGGER audit_trigger_' || quote_ident(TG_TABLE_NAME) ||
                ' AFTER INSERT OR UPDATE OR DELETE ON ' || quote_ident(TG_SCHEMA_NAME) || '.' || quote_ident(TG_TABLE_NAME) ||
                ' FOR EACH ROW EXECUTE PROCEDURE autoaudit.audit_function()';
    END IF;
    RETURN NULL; -- No se devuelve nada en este caso
END;
$$
 LANGUAGE plpgsql;
 
 --DISPARADOR
CREATE OR REPLACE FUNCTION autoaudit.ddl_handler()
RETURNS event_trigger AS $$
DECLARE
    obj record;
    tableName TEXT;
BEGIN
    FOR obj IN SELECT * FROM pg_event_trigger_ddl_commands() WHERE command_tag = 'CREATE TABLE' LOOP
        tableName := split_part(obj.object_identity, '.', 2); -- Extraer el nombre de la tabla
        EXECUTE 'CREATE TRIGGER audit_trigger_' || quote_ident(tableName) ||
                ' AFTER INSERT OR UPDATE OR DELETE ON ' || quote_ident(obj.schema_name) || '.' || quote_ident(tableName) ||
                ' FOR EACH ROW EXECUTE PROCEDURE autoaudit.audit_function()';
    END LOOP;
END;
$$
 LANGUAGE plpgsql;

CREATE EVENT TRIGGER autoaudit_ddl_trigger
    ON ddl_command_end
    WHEN TAG IN ('CREATE TABLE')
    EXECUTE FUNCTION autoaudit.ddl_handler();