package org.mule.routing.filters.antivirus.spi;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.pool.BasePoolableObjectFactory;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.mule.util.FileUtils;

public abstract class AbstractTCPBasedScannerProvider implements
        ScannerProvider
{

    protected transient Log logger = LogFactory.getLog(getClass());

    protected String host = "localhost";
    protected int port = -1;
    protected String version = null;
    protected GenericObjectPool pool;
    protected Properties props;

    public synchronized void dispose()
    {

        if (pool == null)
        {
            return;
        }

        // pool.clear();

        try
        {
            pool.close();

        }
        catch (final Exception e)
        {
            logger.error("Error freeing ressources: " + e);
        }

        pool = null;
        props = null;

    }

    protected abstract void initSocket(final Socket s) throws IOException;

    public synchronized void init(final Properties options)
            throws ScannerException
    {

        if (pool != null)
        {
            throw new ScannerException("Already initialized");
        }

        if ((options != null) && !options.isEmpty())
        {
            host = options.getProperty("host", host);
            port = Integer.parseInt(options.getProperty("port", String
                    .valueOf(port)));

            props = new Properties();
            props.putAll(options);

        }

        pool = new GenericObjectPool(new SocketObjectPool(host, port));
        // pool.setMaxActive(15);
        // pool.setMaxIdle(15);
        // pool.setMaxWait(500);
        pool.setWhenExhaustedAction(GenericObjectPool.WHEN_EXHAUSTED_GROW);
        pool.setTestOnBorrow(true);
        // pool.setTestOnReturn(true);

        // pool.setTestWhileIdle(true);
        // pool.setTimeBetweenEvictionRunsMillis(10 * 60 * 1000);

        logger.debug("Connect to " + host + ":" + port);

        Socket s = null;

        try
        {
            s = (Socket) pool.borrowObject();
        }
        catch (final Exception e)
        {
            throw new ScannerException(e);
        }

        if (version == null)
        {
            throw new ScannerException(
                    "Init failed: no valid response from server");
        }

        try
        {
            pool.returnObject(s);
        }
        catch (final Exception e)
        {
            throw new ScannerException(e);
        }

        logger.debug("init successfully completed");

    }

    protected String writeAndRead(final String s, final OutputStream out,
            final BufferedReader d) throws IOException
    {
        write(s, out);
        final String res = fillAnswer(d);
        logger.debug("  <- " + res);
        return res;
    }

    protected void write(final String s, final OutputStream out)
            throws IOException
    {
        logger.debug("-> " + s);
        out.write((s + "\n").getBytes());
    }

    protected abstract boolean isError(final String lastAnswer);

    protected abstract String fillAnswer(final BufferedReader d)
            throws IOException;

    protected abstract boolean isVirus(final String lastAnswer);

    protected abstract String getScanCommand(final File file);

    protected String scan0(final File file, final OutputStream out,
            final BufferedReader d) throws VirusFoundException,
            ScannerException, IOException
    {

        final String result = writeAndRead(getScanCommand(file), out, d);

        if (isError(result))
        {
            throw new ScannerException("lastAnswer: '" + result + "'");
        }
        else
        {

            logger.debug(file.length() + " bytes scanned in "
                    + file.getAbsolutePath());

            if (isVirus(result))
            {

                logger.info("Virus found in " + file.getAbsolutePath() + "("
                        + result + ")");
                throw new VirusFoundException(result);
            }
            else
            {

                logger.debug("No Virus found in " + file.getAbsolutePath());
                return result;
            }

        }

    }

    public String getVersion()
    {
        // TODO Auto-generated method stub
        return version;
    }

    public String scan(final InputStream in) throws VirusFoundException,
            ScannerException, IOException
    {

        File f = null;

        try
        {
            f = File.createTempFile("mule_virscan_"
                    + System.currentTimeMillis(), ".tmp");

            FileUtils.copyStreamToFile(in, f);

            return scan(f);

        }
        finally
        {
            if (f != null)
            {
                if (!f.delete())
                {
                    logger.warn("Unable to delete temp file "
                            + f.getAbsolutePath());
                }
            }
        }

    }

    public String scan(final File file) throws VirusFoundException,
            ScannerException, IOException
    {

        Socket s = null;
        String result = null;

        OutputStream out;
        BufferedReader d;

        if (pool == null)
        {
            throw new ScannerException("Not initialized");
        }

        try
        {

            s = (Socket) pool.borrowObject();
        }
        catch (final Exception e)
        {
            throw new ScannerException(e);
        }
        out = s.getOutputStream();
        d = new BufferedReader(new InputStreamReader(s.getInputStream()));

        result = scan0(file, out, d);

        try
        {
            pool.returnObject(s);
        }
        catch (final Exception e)
        {
            throw new ScannerException(e);
        }

        return result;

    }

    protected class SocketObjectPool extends BasePoolableObjectFactory
    {
        private String host = null;
        private int port = -1;

        public SocketObjectPool(final String host, final int port)
        {
            super();
            this.host = host;
            this.port = port;
        }

        @Override
        public void destroyObject(Object obj) throws Exception
        {

            if (obj != null)
            {
                ((Socket) obj).close();
            }

            obj = null;

        }

        @Override
        public Object makeObject() throws Exception
        {

            final Socket s = new Socket(host, port);
            initSocket(s);
            return s;
        }

        @Override
        public boolean validateObject(final Object obj)
        {

            if (obj == null)
            {
                return false;
            }

            logger.debug("validateObject ...");
            final boolean result = ((Socket) obj).isConnected()
                    && ((Socket) obj).isBound();
            logger.debug("validateObject finished: " + result);
            return result;
        }

        @Override
        public void activateObject(final Object obj) throws Exception
        {

        }

        @Override
        public void passivateObject(final Object obj) throws Exception
        {

        }

    }

}
