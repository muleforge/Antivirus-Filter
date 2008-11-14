package org.mule.routing.filters.antivirus.spi.clamav;

import org.mule.routing.filters.antivirus.spi.AbstractScannerProviderTestCase;
import org.mule.routing.filters.antivirus.spi.ScannerProvider;

public class ClamAVScannerProviderTestCase extends
        AbstractScannerProviderTestCase
{

    @Override
    protected ScannerProvider getScannerProvider()
    {

        final ClamAVTCPScannerProvider p = new ClamAVTCPScannerProvider();
        p.setPort(9998);
        return p;
    }

}
