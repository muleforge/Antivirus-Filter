package org.mule.routing.filters.antivirus.spi;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;

import junit.framework.TestCase;

public abstract class AbstractScannerProviderTestCase extends TestCase
{
    private ScannerProvider p = null;

    protected abstract ScannerProvider getScannerProvider();

    @Override
    protected void setUp() throws Exception
    {
        // TODO Auto-generated method stub
        super.setUp();
        p = getScannerProvider();
    }

    @Override
    protected void tearDown() throws Exception
    {
        p.dispose();
        p = null;
        super.tearDown();

    }

    public void testScan() throws ScannerException, IOException
    {

        p.init(null);

        try
        {
            p.scan(new File("src/test/resources/virusfiles/novir.txt"));

        }
        catch (final VirusFoundException e)
        {

            fail();

        }

        try
        {
            p
                    .scan(new File(
                            "src/test/resources/virusfiles/novir_enc1.doc.asc"));

        }
        catch (final VirusFoundException e)
        {

            fail();

        }

        try
        {
            final String res = p.scan(new File(
                    "src/test/resources/virusfiles/novir.txt.zip"));

        }
        catch (final VirusFoundException e)
        {

            fail();
        }
        try
        {
            p.scan(new File("src/test/resources/virusfiles/notfound"));
            fail();

        }
        catch (final ScannerException e)
        {

        }
        catch (final VirusFoundException e)
        {

            fail();
        }

        try
        {
            p.scan(new File("src/test/resources/virusfiles/eicar.com.txt"));
            fail();

        }
        catch (final VirusFoundException e)
        {

        }

        try
        {
            p.scan(new File("src/test/resources/virusfiles/eicar_com.zip"));
            fail();

        }
        catch (final VirusFoundException e)
        {

        }

        try
        {
            p.scan(new File("src/test/resources/virusfiles/eicar.com.txt"));
            fail();

        }
        catch (final VirusFoundException e)
        {

        }
        try
        {
            p.scan(new File("src/test/resources/virusfiles/eicarcom2.zip"));
            fail();

        }
        catch (final VirusFoundException e)
        {

        }

        try
        {
            p.scan(new ByteArrayInputStream(new byte[]
            {2, 3, 1, 1, 1}));
        }
        catch (final VirusFoundException e)
        {

            fail();
        }

    }

    public void testScanInit()
    {

        try
        {
            p.init(null);
        }
        catch (final ScannerException e)
        {
            fail();
        }
        try
        {
            p.init(null);
            fail();
        }
        catch (final ScannerException e)
        {

        }

    }

    public void testScanDispose()
    {

        try
        {
            p.init(null);

            assertNotNull(p.getName());
            assertNotNull(p.getVersion());
            assertTrue(p.getName().length() > 0);
            assertTrue(p.getVersion().length() > 0);

        }
        catch (final ScannerException e)
        {
            fail();
        }
        try
        {
            p.dispose();

        }
        catch (final Exception e)
        {
            fail();
        }

        try
        {
            p.scan(new File("."));
            fail();
        }
        catch (final Exception e)
        {

        }

    }

}
