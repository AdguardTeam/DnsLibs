package com.adguard.testapp;

import android.Manifest;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Bundle;
import android.text.Html;
import android.text.Spanned;
import android.view.View;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import android.util.Log;

public class MainActivity extends AppCompatActivity {

    private static final int VPN_PREPARE_REQUEST = 1;

    private static final ScheduledExecutorService scheduler = new ScheduledThreadPoolExecutor(1);

    Context context;

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    public void verifyStoragePermissions() {
        // Check if we have write permission
        int permission = ActivityCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            // We don't have permission so prompt the user
            ActivityCompat.requestPermissions(
                    this,
                    PERMISSIONS_STORAGE,
                    REQUEST_EXTERNAL_STORAGE
            );
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        context = getApplicationContext();

        setContentView(R.layout.activity_main);

        showInterfaceInfo();

        verifyStoragePermissions();

        if (DnsTunVpnService.getLastVpnService() != null &&
                DnsTunVpnService.getLastVpnService().isStarted()) {
            setButtonStarted();
        } else {
            setButtonNotStarted();
        }

        CheckBox checkBox = (CheckBox) findViewById(R.id.pcap_button);
        if (checkBox != null) {
            checkBox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    TcpIpStackSettings.WRITE_PCAP = isChecked;
                }
            });
        }
    }

    private void showToast(final String message) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Context context = getApplicationContext();
                int duration = Toast.LENGTH_SHORT;

                Toast toast = Toast.makeText(context, message, duration);
                toast.show();
            }
        });
    }

    private void showInterfaceInfo() {
        scheduler.schedule(new Runnable() {
            @Override
            public void run() {
                List<String> interfaceInfos = new ArrayList<>();
                try {
                    Enumeration<NetworkInterface> it = NetworkInterface.getNetworkInterfaces();
                    while (it.hasMoreElements()) {
                        NetworkInterface iface = it.nextElement();
                        StringBuilder sb = new StringBuilder(25);
                        boolean hasAddresses = false;
                        sb.append("<p><big><b>");
                        sb.append(iface.getDisplayName());
                        sb.append("</b></big>");
                        sb.append(" MTU: ");
                        sb.append(iface.getMTU());
                        sb.append("<br/><small><small><small><br/></small></small></small><tt>");
                        for (InterfaceAddress address : iface.getInterfaceAddresses()) {
                            if (!address.getAddress().isLinkLocalAddress()) {
                                if (hasAddresses) {
                                    sb.append("<br/>");
                                }
                                sb.append(address.getAddress().getHostAddress().split("%")[0]);
                                sb.append("/");
                                sb.append(address.getNetworkPrefixLength());
                                hasAddresses = true;
                            }
                        }
                        sb.append("</tt></p><small><small><small><br/></small></small></small>");
                        if (hasAddresses) {
                            interfaceInfos.add(sb.toString());
                        }
                    }
                } catch (SocketException e) {
                    e.printStackTrace();
                }
                Collections.sort(interfaceInfos, new Comparator<String>() {
                    @Override
                    public int compare(String lhs, String rhs) {
                        int lct = lhs.contains("tun") ? 0 : 1;
                        int rct = rhs.contains("tun") ? 0 : 1;
                        if (rct != lct) {
                            return lct - rct;
                        }
                        return String.CASE_INSENSITIVE_ORDER.compare(lhs, rhs);
                    }
                });
                String html3text = "";
                for (String info : interfaceInfos) {
                    html3text += info;
                }
                final Spanned html3 = Html.fromHtml(html3text);
                MainActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        TextView view = (TextView) findViewById(R.id.interface_info_textview);
                        if (view != null) {
                            view.setText(html3);
                        }
                    }
                });
            }
        }, 200, TimeUnit.MILLISECONDS);
    }

    private void setButtonNotStarted() {
        ImageButton button = (ImageButton) findViewById(R.id.startstop_button);
        if (button != null) {
            button.setBackgroundResource(R.drawable.button_background_gray);
            button.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    startVpn();
                }
            });
        }
        showInterfaceInfo();
    }

    private void setButtonStarted() {
        ImageButton button = (ImageButton) findViewById(R.id.startstop_button);
        if (button != null) {
            button.setBackgroundResource(R.drawable.button_background_green);
            button.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    stopVpn();
                }
            });
        }
        showInterfaceInfo();
    }

    private void setButtonDoNothing() {
        ImageButton button = (ImageButton) findViewById(R.id.startstop_button);
        if (button != null) {
            button.setOnClickListener(null);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        showInterfaceInfo();
    }

    private void stopVpn() {
        setButtonDoNothing();
        Intent intent = new Intent(context, DnsTunVpnService.class);
        intent.putExtra(DnsTunVpnService.ACTION, DnsTunVpnService.STOP);
        ComponentName serviceName = context.startService(intent);
        if (serviceName != null) {
            setButtonNotStarted();
        }
    }

    private void startVpn() {
        try {
            Intent localIntent = VpnService.prepare(getApplicationContext());
            if (localIntent != null) {
                startActivityForResult(VpnService.prepare(getApplicationContext()), VPN_PREPARE_REQUEST);
                return;
            }
            onVpnServiceReady();
        } catch (ActivityNotFoundException ex) {
            /* it seems some devices, even though they come with Android 4,
            * don't have the VPN components built into the system image.
			* com.android.vpndialogs/com.android.vpndialogs.ConfirmDialog
			* will not be found then */
            Log.e("DnsTunApp", "Error while preparing vpn, Activity not found", ex);
            return;
        } catch (NullPointerException ex) {
            Log.e("DnsTunApp", "Error while preparing vpn, prepare() not ready", ex);
            return;
        } catch (Exception ex) {
            return;
        }
    }

    private void onVpnServiceReady() {
        setButtonDoNothing();
        Intent intent = new Intent(context, DnsTunVpnService.class);
        intent.putExtra(DnsTunVpnService.ACTION, DnsTunVpnService.START);
        ComponentName serviceName = context.startService(intent);
        if (serviceName != null) {
            setButtonStarted();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_PREPARE_REQUEST) {
            onVpnServiceReady();
        }
    }
}
