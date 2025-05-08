package org.bouncycastle.util;

import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;

/**
 * Utility method for accessing system properties.
 */
public class Properties
{

    /**
     * Return whether a particular override has been set to true.
     *
     * @param propertyName the property name for the override.
     * @return true if the property is set to "true", false otherwise.
     */
    public static boolean isOverrideSet(String propertyName)
    {
        try
        {
            return isSetTrue(getPropertyValue(propertyName));
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    /**
     * Return whether a particular override has been set to false.
     *
     * @param propertyName the property name for the override.
     * @param isTrue true if the override should be true, false otherwise.
     * @return true if the property is set to the value of isTrue, false otherwise.
     */
    public static boolean isOverrideSetTo(String propertyName, boolean isTrue)
    {
        try
        {
            String propertyValue = getPropertyValue(propertyName);
            if (isTrue)
            {
                return isSetTrue(propertyValue);
            }
            return isSetFalse(propertyValue);
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    /**
     * Return propertyName as an integer, defaultValue used if not defined.
     *
     * @param propertyName name of property.
     * @param defaultValue integer to return if property not defined.
     * @return value of property, or default if not found, as an int.
     */
    public static int asInteger(String propertyName, int defaultValue)
    {
        String p = getPropertyValue(propertyName);

        if (p != null)
        {
            return Integer.parseInt(p);
        }

        return defaultValue;
    }

    public static String getPropertyValue(final String propertyName)
    {
        return AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                String v = Security.getProperty(propertyName);
                if (v != null)
                {
                    return v;
                }
                return System.getProperty(propertyName);
            }
        });
    }

    public static String getPropertyValue(final String propertyName, final String alternative)
    {
        return AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                String v = Security.getProperty(propertyName);
                if (v != null)
                {
                    return v;
                }
                v = System.getProperty(propertyName);
                if (v != null)
                {
                    return v;
                }
                return alternative;
            }
        });
    }

    private static boolean isSetFalse(String p)
    {
        if (p == null || p.length() != 5)
        {
            return false;
        }

        return (p.charAt(0) == 'f' || p.charAt(0) == 'F')
            && (p.charAt(1) == 'a' || p.charAt(1) == 'A')
            && (p.charAt(2) == 'l' || p.charAt(2) == 'L')
            && (p.charAt(3) == 's' || p.charAt(3) == 'S')
            && (p.charAt(4) == 'e' || p.charAt(4) == 'E');
    }

    private static boolean isSetTrue(String p)
    {
        if (p == null || p.length() != 4)
        {
            return false;
        }

        return (p.charAt(0) == 't' || p.charAt(0) == 'T')
            && (p.charAt(1) == 'r' || p.charAt(1) == 'R')
            && (p.charAt(2) == 'u' || p.charAt(2) == 'U')
            && (p.charAt(3) == 'e' || p.charAt(3) == 'E');
    }
}
