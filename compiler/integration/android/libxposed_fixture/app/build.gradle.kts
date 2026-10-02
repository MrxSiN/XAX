plugins { id("com.android.application") }
android {
  namespace = "org.xax.nativefixture"
  compileSdk = 35
  defaultConfig { applicationId = "org.xax.nativefixture"; minSdk = 23; targetSdk = 35; versionCode = 1; versionName = "1" }
  packaging { resources { merges += "META-INF/xposed/*" } }
}
