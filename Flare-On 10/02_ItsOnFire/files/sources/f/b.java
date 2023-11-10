package f;

import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.net.Uri;
import androidx.compose.runtime.internal.StabilityInferred;
import androidx.core.content.FileProvider;
import com.google.android.gms.common.GoogleApiAvailabilityLight;
import com.secure.itsonfire.R;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Metadata;
import kotlin.io.FilesKt__FileReadWriteKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.Charsets;
import kotlin.text.StringsKt___StringsKt;
import org.jetbrains.annotations.NotNull;
@StabilityInferred(parameters = 0)
@Metadata(bv = {}, d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\bÇ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u001a\u0010\u001bJ*\u0010\n\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\bH\u0002J\u0010\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\u0004H\u0002J\u0010\u0010\u0010\u001a\u00020\u00022\u0006\u0010\u000f\u001a\u00020\u000eH\u0002J\u0018\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u000f\u001a\u00020\u000eH\u0002J\u001a\u0010\u0017\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0016\u001a\u00020\u00152\u0006\u0010\u0012\u001a\u00020\u0011H\u0002J\u0016\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0012\u001a\u00020\u0011¨\u0006\u001c"}, d2 = {"Lf/b;", "", "", "algorithm", "", "input", "Ljavax/crypto/spec/SecretKeySpec;", "key", "Ljavax/crypto/spec/IvParameterSpec;", "iv", "b", "value", "", "a", "Landroid/content/Context;", "context", GoogleApiAvailabilityLight.TRACKING_SOURCE_DIALOG, "", "resourceId", "Ljava/io/File;", "c", "Landroid/content/res/Resources;", "res", "e", "Landroid/content/Intent;", "f", "<init>", "()V", "app_release"}, k = 1, mv = {1, 6, 0})
/* loaded from: classes.dex */
public final class b {
    @NotNull

    /* renamed from: a  reason: collision with root package name */
    public static final b f360a = new b();

    /* renamed from: b  reason: collision with root package name */
    public static final int f361b = 0;

    private b() {
    }

    private final long a(byte[] bArr) {
        CRC32 crc32 = new CRC32();
        crc32.update(bArr);
        return crc32.getValue();
    }

    private final byte[] b(String str, byte[] bArr, SecretKeySpec secretKeySpec, IvParameterSpec ivParameterSpec) {
        Cipher instance = Cipher.getInstance(str);
        instance.init(2, secretKeySpec, ivParameterSpec);
        byte[] doFinal = instance.doFinal(bArr);
        Intrinsics.checkNotNullExpressionValue(doFinal, "cipher.doFinal(input)");
        return doFinal;
    }

    private final File c(int i2, Context context) {
        Resources resources = context.getResources();
        Intrinsics.checkNotNullExpressionValue(resources, "context.resources");
        byte[] e2 = e(resources, i2);
        String d2 = d(context);
        Charset charset = Charsets.UTF_8;
        byte[] bytes = d2.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, context.getString(R.string.f2319b));
        String string = context.getString(R.string.f2321d);
        Intrinsics.checkNotNullExpressionValue(string, "context.getString(R.string.alg)");
        String string2 = context.getString(R.string.f2337t);
        Intrinsics.checkNotNullExpressionValue(string2, "context.getString(\n     …             R.string.iv)");
        byte[] bytes2 = string2.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(bytes2, "this as java.lang.String).getBytes(charset)");
        byte[] b2 = b(string, e2, secretKeySpec, new IvParameterSpec(bytes2));
        File file = new File(context.getCacheDir(), context.getString(R.string.D));
        FilesKt__FileReadWriteKt.writeBytes(file, b2);
        return file;
    }

    private final String d(Context context) {
        String string = context.getString(R.string.f2325h);
        Intrinsics.checkNotNullExpressionValue(string, "context.getString(R.string.c2)");
        String string2 = context.getString(R.string.O);
        Intrinsics.checkNotNullExpressionValue(string2, "context.getString(R.string.w1)");
        StringBuilder sb = new StringBuilder();
        sb.append(string.subSequence(4, 10));
        sb.append(string2.subSequence(2, 5));
        String sb2 = sb.toString();
        Intrinsics.checkNotNullExpressionValue(sb2, "StringBuilder().apply(builderAction).toString()");
        byte[] bytes = sb2.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        long a2 = a(bytes);
        StringBuilder sb3 = new StringBuilder();
        sb3.append(a2);
        sb3.append(a2);
        String sb4 = sb3.toString();
        Intrinsics.checkNotNullExpressionValue(sb4, "StringBuilder().apply(builderAction).toString()");
        return StringsKt___StringsKt.slice(sb4, new IntRange(0, 15));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v0, types: [android.content.res.Resources] */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.io.InputStream] */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v5, types: [java.lang.Throwable, java.io.IOException] */
    /* JADX WARN: Type inference failed for: r2v8 */
    private final byte[] e(Resources e2, int i2) {
        Throwable th;
        IOException e3;
        InputStream inputStream;
        try {
        } catch (Throwable th2) {
            th = th2;
        }
        try {
            inputStream = e2.openRawResource(i2);
            try {
                byte[] bArr = new byte[inputStream.available()];
                inputStream.read(bArr);
                try {
                    Intrinsics.checkNotNull(inputStream);
                    inputStream.close();
                } catch (IOException e4) {
                    e4.printStackTrace();
                }
                return bArr;
            } catch (IOException e5) {
                e3 = e5;
                e3.printStackTrace();
                try {
                    Intrinsics.checkNotNull(inputStream);
                    inputStream.close();
                    return null;
                } catch (IOException e6) {
                    e2 = e6;
                    e2.printStackTrace();
                    return null;
                }
            }
        } catch (IOException e7) {
            e3 = e7;
            inputStream = null;
        } catch (Throwable th3) {
            th = th3;
            e2 = 0;
            try {
                Intrinsics.checkNotNull(e2);
                e2.close();
            } catch (IOException e8) {
                e8.printStackTrace();
            }
            throw th;
        }
    }

    @NotNull
    public final Intent f(@NotNull Context context, int i2) {
        Intrinsics.checkNotNullParameter(context, "context");
        Uri uriForFile = FileProvider.getUriForFile(context, Intrinsics.stringPlus(context.getApplicationContext().getPackageName(), context.getString(R.string.E)), c(i2, context));
        Intent intent = new Intent(context.getString(R.string.f2320c));
        intent.addFlags(32768);
        intent.addFlags(268435456);
        intent.addFlags(1);
        intent.setType(context.getString(R.string.z));
        intent.putExtra(context.getString(R.string.f2327j), uriForFile);
        return intent;
    }
}
