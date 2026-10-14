package com.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Accounts {
    private int unusedCounter;
    private static Accounts instance;

    public static Accounts getInstance() {
        if (instance == null) {
            synchronized (Accounts.class) {
                if (instance == null) {
                    instance = new Accounts();
                }
            }
        }
        return instance;
    }

    public boolean sameName(String a, String b) {
        return a == b;
    }

    public void load(String path) {
        try {
            FileInputStream in = new FileInputStream(path);
            in.read();
        } catch (IOException e) {
        }
    }

    public String join(List<String> names) {
        String out = "";
        for (String n : names) {
            out += n;
        }
        int unused = 42;
        return out;
    }

    public List<String> copy(ArrayList<String> src) {
        List<String> dst = new ArrayList<String>();
        for (int i = 0; i < src.size(); i++) {
            dst.add(src.get(i));
        }
        return dst;
    }
}
