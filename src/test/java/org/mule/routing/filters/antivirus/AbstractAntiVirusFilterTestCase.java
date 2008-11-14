package org.mule.routing.filters.antivirus;

import org.mule.api.MuleMessage;
import org.mule.module.client.MuleClient;
import org.mule.tck.FunctionalTestCase;

public abstract class AbstractAntiVirusFilterTestCase extends
        FunctionalTestCase
{

    public void testFilter() throws Exception
    {
        final MuleClient client = new MuleClient();
        MuleMessage msg = null;
        int i = 0;

        while ((msg = client.request("vm://out", 2000)) != null)
        {
            // logger.debug(i+": "+msg.getPayloadAsString());
            i++;
        }

        logger.debug(i + " msgs");
        assertTrue(i == 5); // 4 are non-virus files

        // client.dispose();

    }

}
