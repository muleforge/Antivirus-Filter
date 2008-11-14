package org.mule.routing.filters.antivirus.spi.clamav;

import org.mule.routing.filters.antivirus.AbstractAntiVirusFilterTestCase;

public class ClamAVAntiVirusFilterTestCase extends
        AbstractAntiVirusFilterTestCase
{

    @Override
    protected String getConfigResources()
    {
        // TODO Auto-generated method stub
        return "clamav-config.xml";
    }

}
