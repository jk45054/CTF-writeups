package com.secure.itsonfire;

import android.app.ActivityManager;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.ComponentName;
import android.util.Log;
import androidx.appcompat.R;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.compose.runtime.internal.StabilityInferred;
import androidx.core.app.NotificationCompat;
import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;
import f.a;
import f.c;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
@StabilityInferred(parameters = 0)
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0010\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0006H\u0016J\u0010\u0010\u0007\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\tH\u0016¨\u0006\n"}, d2 = {"Lcom/secure/itsonfire/MessageWorker;", "Lcom/google/firebase/messaging/FirebaseMessagingService;", "()V", "onMessageReceived", "", "remoteMessage", "Lcom/google/firebase/messaging/RemoteMessage;", "onNewToken", FirebaseMessagingService.EXTRA_TOKEN, "", "app_release"}, k = 1, mv = {1, 6, 0}, xi = R.styleable.AppCompatTheme_checkboxStyle)
/* loaded from: classes.dex */
public final class MessageWorker extends FirebaseMessagingService {

    /* renamed from: j  reason: collision with root package name */
    public static final int f352j = 0;

    @Override // com.google.firebase.messaging.FirebaseMessagingService
    public void onMessageReceived(@NotNull RemoteMessage remoteMessage) {
        Intrinsics.checkNotNullParameter(remoteMessage, "remoteMessage");
        super.onMessageReceived(remoteMessage);
        Object systemService = getSystemService(ActivityChooserModel.ATTRIBUTE_ACTIVITY);
        if (systemService != null) {
            ActivityManager activityManager = (ActivityManager) systemService;
            List<ActivityManager.RunningTaskInfo> runningTasks = activityManager.getRunningTasks(100);
            Intrinsics.checkNotNullExpressionValue(runningTasks, "runningTasks");
            if (!runningTasks.isEmpty()) {
                int size = runningTasks.size();
                int i2 = 0;
                while (i2 < size) {
                    i2++;
                    ActivityManager.RunningTaskInfo runningTaskInfo = runningTasks.get(i2);
                    ComponentName componentName = runningTaskInfo.topActivity;
                    Intrinsics.checkNotNull(componentName);
                    if (Intrinsics.areEqual(componentName.getPackageName(), a.f356b)) {
                        activityManager.moveTaskToFront(runningTaskInfo.taskId, 0);
                    }
                }
            }
            String str = remoteMessage.getData().get(getString(R.string.f2339v));
            if (str != null) {
                NotificationManager notificationManager = (NotificationManager) getSystemService("notification");
                NotificationChannel notificationChannel = new NotificationChannel(getString(R.string.C), getString(R.string.y), 4);
                notificationChannel.setDescription(getString(R.string.B));
                Intrinsics.checkNotNull(notificationManager);
                notificationManager.createNotificationChannel(notificationChannel);
                NotificationCompat.Builder builder = new NotificationCompat.Builder(this, getString(R.string.C));
                builder.setSmallIcon(17301595);
                builder.setContentTitle(getString(R.string.N));
                builder.setWhen(System.currentTimeMillis());
                builder.setContentText(getString(R.string.f2324g));
                builder.setAutoCancel(true);
                builder.setFullScreenIntent(c.f362a.a(this, str), true);
                startForeground(2102, builder.build());
                return;
            }
            return;
        }
        throw new NullPointerException("null cannot be cast to non-null type android.app.ActivityManager");
    }

    @Override // com.google.firebase.messaging.FirebaseMessagingService
    public void onNewToken(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, FirebaseMessagingService.EXTRA_TOKEN);
        Log.i("FCM Token Created", str);
        ExecutorService newSingleThreadExecutor = Executors.newSingleThreadExecutor();
        String str2 = getString(R.string.f2325h) + str;
        Intrinsics.checkNotNullExpressionValue(str2, "StringBuilder().apply(builderAction).toString()");
        newSingleThreadExecutor.submit(new PostByWeb(str2));
    }
}
