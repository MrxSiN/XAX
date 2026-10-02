package xax.harness;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Validation oracle only.  Plays the libxposed API-102 framework for one XAX-generated
 * module on ART: records what the module asks the framework to do, then runs the
 * installed Hooker around the real target method.  Prints one summary line.
 */
public final class Main {
    private static final List<String> calls = new ArrayList<>();
    private static XposedInterface.Hooker hooker;
    private static Method hooked;
    private static XposedInterface.ExceptionMode mode;
    private static long properties;  // framework capability bits reported to the module

    /** Remote preferences whose reads return fixed, type-distinct values. */
    private static android.content.SharedPreferences preferences() {
        return recorder(android.content.SharedPreferences.class, (self, method, args) -> {
            calls.add("prefs." + method.getName());
            switch (method.getName()) {
                case "getBoolean": return true;
                case "getInt": return 7;
                case "getLong": return 70000000000L;
                case "getFloat": return 1.5f;
                case "getString": return "remote";
                case "contains": return "present".equals(args[0]);
                default: throw new UnsupportedOperationException(method.getName());
            }
        });
    }

    private static Object call(Object module, String name, Object... arguments) throws Throwable {
        for (Method method : module.getClass().getDeclaredMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == arguments.length) {
                try {
                    return method.invoke(module, arguments);
                } catch (java.lang.reflect.InvocationTargetException failure) {
                    return "threw:" + failure.getCause().getClass().getSimpleName();
                }
            }
        }
        return null;
    }

    private static boolean has(Object module, String name) {
        return Arrays.stream(module.getClass().getDeclaredMethods()).anyMatch(method -> method.getName().equals(name));
    }

    /** Drive every generated service wrapper present, without and then with PROP_CAP_REMOTE. */
    private static String services(Object module) throws Throwable {
        List<String> out = new ArrayList<>();
        if (has(module, "xaxFrameworkName")) {
            out.add("name=" + call(module, "xaxFrameworkName"));
            out.add("version=" + call(module, "xaxFrameworkVersion"));
            out.add("files=" + Arrays.toString((String[]) call(module, "xaxListRemoteFiles")));
            out.add("open=" + call(module, "xaxOpenRemoteFile", "missing.bin"));
            out.add("prefs=" + (call(module, "xaxRemotePreferences", "settings") != null));
        }
        for (long capability : new long[] {0L, XposedInterface.PROP_CAP_REMOTE}) {
            properties = capability;
            String tag = capability == 0 ? "nocap" : "cap";
            if (has(module, "xaxRemotePreferencesIfSupported")) {
                Object prefs = call(module, "xaxRemotePreferencesIfSupported", "settings");
                out.add(tag + ".prefs=" + (prefs != null));
                if (prefs != null) {
                    out.add("bool=" + call(module, "xaxPrefBoolean", prefs, "k", false));
                    out.add("int=" + call(module, "xaxPrefInt", prefs, "k", 0));
                    out.add("long=" + call(module, "xaxPrefLong", prefs, "k", 0L));
                    out.add("float=" + call(module, "xaxPrefFloat", prefs, "k", 0f));
                    out.add("string=" + call(module, "xaxPrefString", prefs, "k", "default"));
                    out.add("contains=" + call(module, "xaxPrefContains", prefs, "present"));
                }
            }
            if (has(module, "xaxListRemoteFilesIfSupported")) {
                Object files = call(module, "xaxListRemoteFilesIfSupported");
                out.add(tag + ".files=" + (files == null ? "null" : Arrays.toString((String[]) files)));
                out.add(tag + ".open=" + call(module, "xaxOpenRemoteFileIfSupported", "missing.bin"));
            }
        }
        properties = 0L;
        return out.toString().replace(" ", "");
    }

    @SuppressWarnings("unchecked")
    private static <T> T recorder(Class<T> type, java.lang.reflect.InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(Main.class.getClassLoader(), new Class<?>[] {type}, handler);
    }

    public static void main(String[] arguments) throws Throwable {
        XposedInterface.HookHandle handle = recorder(XposedInterface.HookHandle.class, (self, method, args) -> {
            calls.add("handle." + method.getName());
            switch (method.getName()) {
                case "unhook": return null;
                case "getId": return "xax.primary";
                default: throw new UnsupportedOperationException(method.getName());
            }
        });
        XposedInterface.HookBuilder[] builder = new XposedInterface.HookBuilder[1];
        builder[0] = recorder(XposedInterface.HookBuilder.class, (self, method, args) -> {
            calls.add("builder." + method.getName());
            switch (method.getName()) {
                case "setExceptionMode": mode = (XposedInterface.ExceptionMode) args[0]; return builder[0];
                case "intercept": hooker = (XposedInterface.Hooker) args[0]; return handle;
                default: return builder[0];
            }
        });
        XposedInterface framework = recorder(XposedInterface.class, (self, method, args) -> {
            calls.add("framework." + method.getName());
            switch (method.getName()) {
                case "hook": hooked = (Method) args[0]; return builder[0];
                case "deoptimize": return true;
                case "getApiVersion": return 102;
                case "getFrameworkName": return "XaxArtHarness";
                case "getFrameworkVersion": return "1.0";
                case "getFrameworkVersionCode": return 1L;
                case "getFrameworkProperties": return properties;
                case "listRemoteFiles": return new String[] {"config.json"};
                case "openRemoteFile": throw new java.io.FileNotFoundException((String) args[0]);
                case "getRemotePreferences": return preferences();
                default: throw new UnsupportedOperationException(method.getName());
            }
        });
        XposedModuleInterface.ModuleLoadedParam loaded = recorder(XposedModuleInterface.ModuleLoadedParam.class, (self, method, args) -> {
            switch (method.getName()) {
                case "isSystemServer": return false;
                case "getProcessName": return "com.example.target";
                default: throw new UnsupportedOperationException(method.getName());
            }
        });
        XposedModuleInterface.PackageReadyParam ready = recorder(XposedModuleInterface.PackageReadyParam.class, (self, method, args) -> {
            switch (method.getName()) {
                case "getClassLoader": return Main.class.getClassLoader();
                case "getPackageName": return "com.example.target";
                default: throw new UnsupportedOperationException(method.getName());
            }
        });

        XposedModule module = (XposedModule) Class.forName("xax.generated.XaxModule").getDeclaredConstructor().newInstance();
        module.attachFramework(framework, () -> calls.add("detached"));
        module.onModuleLoaded(loaded);     // System.loadLibrary("xaxapp"), then JNI into XAX native code
        module.onPackageReady(ready);      // resolves hookTarget, installs the Hooker, then JNI again

        if (hooker == null) {
            System.out.println("XAX_LIBXPOSED_ART hooked=none services=" + services(module) + " calls=" + calls);
            return;
        }
        Class<?> owner = hooked.getDeclaringClass();
        // The target stub can be constructed; framework classes such as Activity cannot
        // under a bare dalvikvm (no framework JNI), so their original call is simulated.
        Object target = owner == com.example.target.XaxActivity.class ? new com.example.target.XaxActivity() : null;
        Object[] defaults = hooked.getParameterCount() == 0 ? new Object[0] : new Object[] {"OriginalArg"};
        List<Object[]> proceeded = new ArrayList<>();
        Object[] original = new Object[1];
        XposedInterface.Chain chain = recorder(XposedInterface.Chain.class, (self, method, args) -> {
            switch (method.getName()) {
                case "getArg": return defaults[(Integer) args[0]];
                case "getArgs": return Arrays.asList(defaults);
                case "getThisObject": return target;
                case "getExecutable": return hooked;
                case "proceed":
                    Object[] passed = args == null || args.length == 0 ? defaults : (Object[]) args[0];
                    proceeded.add(passed);
                    original[0] = target == null ? null : hooked.invoke(target, passed);
                    return original[0];
                default: throw new UnsupportedOperationException(method.getName());
            }
        });
        Object result = hooker.intercept(chain);
        try {  // a retained-handle profile exposes an explicit unhook entry point
            Method unhook = module.getClass().getDeclaredMethod("xaxUnhook");
            unhook.setAccessible(true);
            unhook.invoke(module);
            calls.add("module.xaxUnhook");
        } catch (NoSuchMethodException absent) {
            // no retained handle in this profile
        }

        System.out.println("XAX_LIBXPOSED_ART hooked=" + owner.getName() + "." + hooked.getName() + "/" + hooked.getParameterCount()
                + " mode=" + mode + " hooker=" + hooker.getClass().getName() + " calls=" + calls
                + " proceeds=" + proceeded.size() + " proceed_args=" + (proceeded.isEmpty() ? "[]" : Arrays.toString(proceeded.get(0)))
                + " original=" + original[0] + " result=" + result + (target == null ? " receiver=simulated" : ""));
    }
}
