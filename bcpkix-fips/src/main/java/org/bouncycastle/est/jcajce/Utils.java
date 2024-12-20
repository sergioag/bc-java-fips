package org.bouncycastle.est.jcajce;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.est.AttrOrOID;
import org.bouncycastle.util.Strings;

class Utils
{
    static AttrOrOID[] clone(AttrOrOID[] ids)
    {
        AttrOrOID[] tmp = new AttrOrOID[ids.length];

        System.arraycopy(ids, 0, tmp, 0, ids.length);

        return tmp;
    }

    static Set<String> asKeySet(String propertyName)
    {
        Set<String> set = new HashSet<String>();

        String p = fetchProperty(propertyName);

        if (p != null)
        {
            StringTokenizer sTok = new StringTokenizer(p, ",");
            while (sTok.hasMoreElements())
            {
                set.add(Strings.toLowerCase(sTok.nextToken()).trim());
            }
        }

        return Collections.unmodifiableSet(set);
    }

    private static String fetchProperty(final String propertyName)
    {
        return (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {

                return System.getProperty(propertyName);
            }
        });
    }
}
