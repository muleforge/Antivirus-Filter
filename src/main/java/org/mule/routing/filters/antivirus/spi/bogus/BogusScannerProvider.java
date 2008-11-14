package org.mule.routing.filters.antivirus.spi.bogus;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.mule.routing.filters.antivirus.spi.ScannerException;
import org.mule.routing.filters.antivirus.spi.ScannerProvider;
import org.mule.routing.filters.antivirus.spi.VirusFoundException;

public class BogusScannerProvider implements ScannerProvider
{

    private int i = 0;

    public void dispose()
    {

    }

    public String getName() throws ScannerException
    {
        // TODO Auto-generated method stub
        return "BogusScanner";
    }

    public String getVersion() throws ScannerException
    {
        // TODO Auto-generated method stub
        return "1.0";
    }

    public void init(final Properties options) throws ScannerException
    {
        // TODO Auto-generated method stub

    }

    public synchronized String scan(final File file)
            throws VirusFoundException, ScannerException, IOException
    {
        i++;

        if (i % 2 == 0)
        {
            throw new VirusFoundException("Bogus Virus found");
        }
        else
        {
            return "OK, No Virus";
        }
    }

    public String scan(final InputStream in) throws VirusFoundException,
            ScannerException, IOException
    {
        // TODO Auto-generated method stub
        return scan((File) null);
    }

}
