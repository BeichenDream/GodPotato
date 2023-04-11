using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace GodPotato
{
    internal class ArgsParse
    {
        [System.AttributeUsage(AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
        public sealed class ArgsAttribute : Attribute
        {
            public string FieldName { get; set; }
            public string DefaultValue { get; set; }
            public bool Required { get; set; }
            public string Description { get; set; }
            public ArgsAttribute(string FieldName, string DefaultValue)
            {
                this.FieldName = FieldName;
                this.DefaultValue = DefaultValue;
            }
        }

        protected static void ParseArgsSetValue(object obj, PropertyInfo propertyInfo, string value)
        {
            Type propertyType = propertyInfo.PropertyType;
            object valueObj = null;
            if (propertyType.IsPrimitive)
            {
                MethodInfo methodInfo = propertyType.GetMethod("Parse", new Type[] { typeof(string) });
                methodInfo.Invoke(null, new object[] { valueObj });
            }
            else if (propertyType == typeof(string))
            {
                valueObj = value;
            }
            else if (propertyType == typeof(string[]))
            {
                string[] values = value.Split(',');
                valueObj = values;
            }
            else if (propertyType == typeof(byte[]))
            {
                valueObj = Convert.FromBase64String(value);
            }
            else if (propertyType.IsArray && propertyType.GetElementType().IsPrimitive)
            {
                Type elementType = propertyType.GetElementType();
                string[] strValues = value.Split(',');
                List<object> values = new List<object>();
                MethodInfo methodInfo = elementType.GetMethod("Parse", new Type[] { typeof(string) });

                foreach (var str in strValues)
                {
                    if (str.Contains("-"))
                    {
                        string[] strRanges = str.Split('-');
                        long startRange = long.Parse(strRanges[0]);
                        long stopRange = long.Parse(strRanges[1]);
                        for (long i = startRange; i <= stopRange; i++)
                        {
                            values.Add((methodInfo.Invoke(null, new object[] { i.ToString() })));
                        }
                    }
                    else
                    {
                        values.Add(methodInfo.Invoke(null, new object[] { str }));
                    }
                }
                Array array = Array.CreateInstance(elementType, values.Count);
                for (int i = 0; i < values.Count; i++)
                {
                    array.SetValue(values[i], i);
                }
                valueObj = array;
            }
            else if (propertyType.IsEnum)
            {
                valueObj = Enum.Parse(propertyType, value);
            }            

            propertyInfo.SetValue(obj, valueObj, null);

        }
        public static T ParseArgs<T>(string[] args)
        {
            Type type = typeof(T);
            Type argsAttributeType = typeof(ArgsAttribute);
            object value = type.GetConstructor(new Type[0]).Invoke(new object[0]);
            PropertyInfo[] propertyInfos = type.GetProperties();
            Dictionary<string, PropertyInfo> propertyInfoDict = new Dictionary<string, PropertyInfo>();
            List<string> requiredPropertyList = new List<string>();
            foreach (PropertyInfo propertyInfo in propertyInfos)
            {
                ArgsAttribute argsAttribute = (ArgsAttribute)Attribute.GetCustomAttribute(propertyInfo, argsAttributeType);
                if (argsAttribute != null)
                {
                    string attributeLower = argsAttribute.FieldName.ToLower();
                    if (argsAttribute.Required)
                    {
                        requiredPropertyList.Add(attributeLower);
                    }
                    propertyInfoDict.Add(attributeLower, propertyInfo);
                    ParseArgsSetValue(value, propertyInfo, argsAttribute.DefaultValue);
                }
            }

            for (int i = 0; i < args.Length; i++)
            {
                string currentArg = args[i];
                if (currentArg.StartsWith("-"))
                {
                    string currentArgName = currentArg.Substring(1).ToLower();
                    if ((i + 1 < args.Length))
                    {
                        i++;
                        string currentArgValue = args[i];

                        PropertyInfo propertyInfo;
                        if (propertyInfoDict.TryGetValue(currentArgName, out propertyInfo))
                        {
                            ParseArgsSetValue(value, propertyInfo, currentArgValue);
                            requiredPropertyList.Remove(currentArgName);
                        }
                    }
                }
            }

            if (requiredPropertyList.Count > 0)
            {
                throw new Exception($"Required Parameter {string.Join(",", requiredPropertyList.ToArray())}");
            }

            return (T)value;
        }
        public static string PrintHelp(Type type,string head,string appName, string[] examples) {;
            Type argsAttributeType = typeof(ArgsAttribute);
            object value = type.GetConstructor(new Type[0]).Invoke(new object[0]);
            PropertyInfo[] propertyInfos = type.GetProperties();
            List<ArgsAttribute> propertyInfoList = new List<ArgsAttribute>();
            List<ArgsAttribute> requiredPropertyList = new List<ArgsAttribute>();
            foreach (PropertyInfo propertyInfo in propertyInfos)
            {
                ArgsAttribute argsAttribute = (ArgsAttribute)Attribute.GetCustomAttribute(propertyInfo, argsAttributeType);
                if (argsAttribute != null)
                {
                    propertyInfoList.Add(argsAttribute);
                    if (argsAttribute.Required)
                    {
                        requiredPropertyList.Add(argsAttribute);
                    }
                }
            }

            StringWriter stringBuilder = new StringWriter();
            stringBuilder.WriteLine(head);
            stringBuilder.WriteLine();
            stringBuilder.WriteLine("Arguments:");
            stringBuilder.WriteLine();
            foreach (var argsAttribute in propertyInfoList)
            {
                stringBuilder.WriteLine("\t-{0} Required:{1} {2} (default {3})", argsAttribute.FieldName, argsAttribute.Required, argsAttribute.Description, argsAttribute.DefaultValue); 
            }
            stringBuilder.WriteLine();
            stringBuilder.WriteLine("Example:");
            stringBuilder.WriteLine();
            foreach (string example in examples)
            {
                stringBuilder.WriteLine(example);
            }

            

            if (requiredPropertyList.Count > 0)
            {
                string requiredExample = "";
                requiredExample = appName + " ";
                foreach (ArgsAttribute argsAttribute in requiredPropertyList)
                {
                    if (argsAttribute.DefaultValue.Contains(" ") || argsAttribute.DefaultValue.Contains("\t") || argsAttribute.DefaultValue.Contains("\r"))
                    {
                        requiredExample += string.Format("-{0} \"{1}\" ", argsAttribute.FieldName, argsAttribute.DefaultValue);
                    }
                    else
                    {
                        requiredExample += string.Format("-{0} {1} ", argsAttribute.FieldName, argsAttribute.DefaultValue);
                    }
                }
                stringBuilder.WriteLine(requiredExample); ;
            }

            if (propertyInfoList.Count > 0 && requiredPropertyList.Count != propertyInfoList.Count)
            {
                string allParameterExample = "";
                allParameterExample = appName + " ";
                foreach (ArgsAttribute argsAttribute in propertyInfoList)
                {
                    if (argsAttribute.DefaultValue.Contains(" ") || argsAttribute.DefaultValue.Contains("\t") || argsAttribute.DefaultValue.Contains("\r"))
                    {
                        allParameterExample += string.Format("-{0} \"{1}\" ", argsAttribute.FieldName, argsAttribute.DefaultValue);
                    }
                    else
                    {
                        allParameterExample += string.Format("-{0} {1} ", argsAttribute.FieldName, argsAttribute.DefaultValue);
                    }
                }
                stringBuilder.WriteLine(allParameterExample); ;
            }



            return stringBuilder.ToString(); 
        }
    }
}
