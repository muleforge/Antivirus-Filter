package org.mule.routing.filters.antivirus.spi;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Implementations must be threadsafe!
 * 
 * @author hsaly
 * 
 */
public interface ScannerProvider
{

    void init(Properties options) throws ScannerException;

    String getName() throws ScannerException;

    String getVersion() throws ScannerException;

    String scan(InputStream in) throws VirusFoundException, ScannerException,
            IOException;

    String scan(File file) throws VirusFoundException, ScannerException,
            IOException;

    /**
     * Release ressources
     */
    void dispose();

}
