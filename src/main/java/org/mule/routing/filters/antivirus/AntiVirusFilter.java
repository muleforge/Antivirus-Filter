package org.mule.routing.filters.antivirus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mule.api.DefaultMuleException;
import org.mule.api.MuleException;
import org.mule.api.MuleMessage;
import org.mule.api.lifecycle.InitialisationException;
import org.mule.api.lifecycle.Lifecycle;
import org.mule.api.routing.filter.Filter;
import org.mule.api.routing.filter.ObjectFilter;
import org.mule.routing.filters.antivirus.spi.ScannerException;
import org.mule.routing.filters.antivirus.spi.ScannerProvider;
import org.mule.routing.filters.antivirus.spi.VirusFoundException;

public class AntiVirusFilter implements Filter, Lifecycle, FileFilter,
        ObjectFilter
{

    protected transient Log logger = LogFactory.getLog(getClass());
    private ScannerProvider provider = null;
    private Properties properties = null;

    public boolean accept(final Object object)
    {

        if (object == null)
        {
            return true;
        }

        try
        {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            final ObjectOutputStream oout = new ObjectOutputStream(out);
            oout.writeObject(object);
            oout.close();
            out.close();

            return accept0(out.toByteArray());
        }
        catch (final IOException e)
        {
            logger.error(e.toString(), e);
            return false;
        }

    }

    public boolean accept(final File file)
    {

        if (file == null)
        {
            return true;
        }

        try
        {
            final String res = provider.scan(file);
            logger.debug("Result: " + res);
            return true;
        }
        catch (final VirusFoundException e)
        {
            // TODO Auto-generated catch block
            logger.warn("Virus found: " + e.toString());
        }
        catch (final ScannerException e)
        {
            // TODO Auto-generated catch block
            logger.error(e.toString(), e);
        }
        catch (final IOException e)
        {
            // TODO Auto-generated catch block
            logger.error(e.toString(), e);
        }
        catch (final Exception e)
        {
            // TODO Auto-generated catch block
            logger.error(e.toString(), e);
        }

        logger.debug("Will not accept this msg!");
        return false;

    }

    public Properties getProperties()
    {
        return properties;
    }

    public void setProperties(final Properties properties)
    {
        this.properties = properties;
    }

    public void stop() throws MuleException
    {
        // TODO Auto-generated method stub
        logger.debug("stop()");
    }

    public void dispose()
    {
        // TODO Auto-generated method stub
        logger.debug("dispose()");

        if (provider != null)
        {
            provider.dispose();
        }
    }

    public void initialise() throws InitialisationException
    {
        // called more than once?
        logger.debug("initialise()");
    }

    public void start() throws MuleException
    {
        // TODO Auto-generated method stub
        logger.debug("start()");
        try
        {
            logger.debug("properties: " + properties);
            provider.init(properties);
        }
        catch (final ScannerException e)
        {
            // TODO Auto-generated catch block
            throw new DefaultMuleException(e);
        }

    }

    public boolean accept(final MuleMessage message)
    {
        // TODO Auto-generated method stub

        try
        {
            return accept0(message.getPayloadAsBytes());
        }
        catch (final Exception e)
        {
            logger.error(e.toString(), e);
            return false;
        }
    }

    private boolean accept0(final byte[] bytes)
    {
        // TODO Auto-generated method stub

        try
        {
            final String res = provider.scan(new ByteArrayInputStream(bytes));
            logger.debug("Result: " + res);
            return true;
        }
        catch (final VirusFoundException e)
        {
            // TODO Auto-generated catch block
            logger.warn("Virus found: " + e.toString());
        }
        catch (final ScannerException e)
        {
            // TODO Auto-generated catch block
            logger.error(e.toString(), e);
        }
        catch (final IOException e)
        {
            // TODO Auto-generated catch block
            logger.error(e.toString(), e);
        }
        catch (final Exception e)
        {
            // TODO Auto-generated catch block
            logger.error(e.toString(), e);
        }

        logger.debug("Will not accept this msg!");
        return false;

    }

    public ScannerProvider getProvider()
    {
        return provider;
    }

    public void setProvider(final ScannerProvider provider)
    {
        this.provider = provider;
    }

}
