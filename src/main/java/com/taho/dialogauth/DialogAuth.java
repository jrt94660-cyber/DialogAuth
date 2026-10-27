package com.taho.dialogauth;

import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickCallback;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.*;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitTask;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DialogAuth extends JavaPlugin implements Listener {
    private final Map<UUID, Long> authenticated = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> attempts = new ConcurrentHashMap<>();
    private final Map<String, ProfileCache> premiumProfiles = new ConcurrentHashMap<>();
    private final Map<UUID, Long> authCheckStarted = new ConcurrentHashMap<>();
    private File usersFile;
    private YamlConfiguration users;
    private long sessionMillis;
    private int maxAttempts;
    private int minPasswordLength;
    private boolean bedrockAutoLogin;
    private boolean premiumAutoLogin;
    private boolean premiumNameDetection;
    private BukkitTask reminderTask;

    private record ProfileCache(String uuid, long expiresAt) { }
    private static final Pattern PROFILE_ID = Pattern.compile("\\\"id\\\"\\s*:\\s*\\\"([0-9a-fA-F]{32})\\\"");

    @Override public void onEnable() {
        saveDefaultConfig();
        loadSettings();
        loadUsers();
        Bukkit.getPluginManager().registerEvents(this, this);
        if (getCommand("dialogauth") != null) getCommand("dialogauth").setExecutor((sender, command, label, args) -> {
            if (args.length == 1 && args[0].equalsIgnoreCase("reload")) {
                if (!sender.hasPermission("dialogauth.admin")) { sender.sendMessage("§cNo permission."); return true; }
                reloadConfig(); loadSettings(); sender.sendMessage("§aDialogAuth configuration reloaded."); return true;
            }
            if (args.length == 2 && args[0].equalsIgnoreCase("unregister")) {
                if (!sender.hasPermission("dialogauth.admin")) { sender.sendMessage("§cNo permission."); return true; }
                String key = args[1].toLowerCase(Locale.ROOT);
                if (!users.contains(key)) { sender.sendMessage("§cNo registered account found for " + args[1] + "."); return true; }
                users.set(key, null); saveUsers(); sender.sendMessage("§aRemoved DialogAuth account for " + args[1] + "."); return true;
            }
            if (args.length == 1 && args[0].equalsIgnoreCase("login") && sender instanceof Player player) {
                showAuthDialog(player); return true;
            }
            sender.sendMessage("§e/dialogauth reload §7- reload config");
            sender.sendMessage("§e/dialogauth unregister <player> §7- remove registration");
            sender.sendMessage("§e/dialogauth login §7- reopen authentication dialog");
            return true;
        });
        reminderTask = Bukkit.getScheduler().runTaskTimer(this, () -> {
            for (Player p : Bukkit.getOnlinePlayers()) {
                if (!isAuthenticated(p) && !authCheckStarted.containsKey(p.getUniqueId())) showAuthDialog(p);
            }
        }, 40L, 40L);
        getLogger().info("DialogAuth enabled.");
    }

    @Override public void onDisable() {
        if (reminderTask != null) reminderTask.cancel();
        saveUsers();
    }

    private void loadSettings() {
        sessionMillis = Math.max(1, getConfig().getLong("session-expiry-minutes", 30)) * 60_000L;
        maxAttempts = Math.max(1, getConfig().getInt("security.max-login-attempts", 5));
        minPasswordLength = Math.max(6, getConfig().getInt("security.min-password-length", 6));
        bedrockAutoLogin = getConfig().getBoolean("auto-login.bedrock", true);
        premiumAutoLogin = getConfig().getBoolean("auto-login.premium-java", true);
        premiumNameDetection = getConfig().getBoolean("premium-name-detection.enabled", true);
    }

    private void loadUsers() {
        if (!getDataFolder().exists()) getDataFolder().mkdirs();
        usersFile = new File(getDataFolder(), "users.yml");
        users = YamlConfiguration.loadConfiguration(usersFile);
    }

    private synchronized void saveUsers() {
        try { users.save(usersFile); } catch (IOException e) { getLogger().severe("Could not save users.yml: " + e.getMessage()); }
    }

    @EventHandler public void onJoin(PlayerJoinEvent event) {
        Player p = event.getPlayer();
        UUID id = p.getUniqueId();
        attempts.remove(id);
        authenticated.remove(id);
        authCheckStarted.put(id, System.currentTimeMillis());

        if (bedrockAutoLogin && isFloodgatePlayer(id)) {
            authCheckStarted.remove(id);
            authenticated.put(id, System.currentTimeMillis());
            p.sendMessage(Component.text("Bedrock player detected; automatic login enabled."));
            return;
        }

        // A Mojang profile lookup plus UUID comparison distinguishes an authenticated
        // premium Java login from a cracked client claiming the same premium username.
        if (premiumNameDetection && premiumAutoLogin) {
            Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
                String premiumUuid = lookupPremiumUuid(p.getName());
                Bukkit.getScheduler().runTask(this, () -> {
                    if (!p.isOnline()) { authCheckStarted.remove(id); return; }
                    if (premiumUuid != null && normalizeUuid(premiumUuid).equals(normalizeUuid(id.toString()))) {
                        authenticated.put(id, System.currentTimeMillis());
                        authCheckStarted.remove(id);
                        p.closeDialog();
                        p.sendMessage(Component.text("Premium Java account verified; automatic login enabled."));
                        return;
                    }
                    // A premium username with an offline/cracked UUID is deliberately NOT
                    // trusted. It must pass password auth even if a previous session exists.
                    boolean premiumNameClaimedByCrackedClient = premiumUuid != null;
                    if (!premiumNameClaimedByCrackedClient) {
                        long lastQuit = getConfig().getLong("sessions." + id, 0L);
                        if (users.contains(p.getName().toLowerCase(Locale.ROOT) + ".password")
                                && lastQuit > 0 && System.currentTimeMillis() - lastQuit < sessionMillis) {
                            authenticated.put(id, System.currentTimeMillis());
                            authCheckStarted.remove(id);
                            return;
                        }
                    }
                    authCheckStarted.remove(id);
                    showAuthDialog(p);
                });
            });
        } else {
            long lastQuit = getConfig().getLong("sessions." + id, 0L);
            if (users.contains(p.getName().toLowerCase(Locale.ROOT) + ".password")
                    && lastQuit > 0 && System.currentTimeMillis() - lastQuit < sessionMillis) {
                authenticated.put(id, System.currentTimeMillis());
                authCheckStarted.remove(id);
            } else {
                authCheckStarted.remove(id);
                Bukkit.getScheduler().runTaskLater(this, () -> {
                    if (p.isOnline() && !isAuthenticated(p)) showAuthDialog(p);
                }, 5L);
            }
        }
        // Give the asynchronous premium lookup time to finish before the periodic reminder.
        Bukkit.getScheduler().runTaskLater(this, () -> {
            if (p.isOnline() && !isAuthenticated(p) && !authCheckStarted.containsKey(id)) showAuthDialog(p);
        }, 100L);
    }

    @EventHandler public void onQuit(PlayerQuitEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        authenticated.remove(id);
        authCheckStarted.remove(id);
        getConfig().set("sessions." + id, System.currentTimeMillis());
        saveConfig();
        attempts.remove(id);
    }

    private boolean isAuthenticated(Player p) {
        Long t = authenticated.get(p.getUniqueId());
        return t != null && System.currentTimeMillis() - t < sessionMillis;
    }

    private void markAuthenticated(Player p) {
        authenticated.put(p.getUniqueId(), System.currentTimeMillis());
        authCheckStarted.remove(p.getUniqueId());
        getConfig().set("sessions." + p.getUniqueId(), System.currentTimeMillis());
        saveConfig();
        p.closeDialog();
        p.sendMessage(Component.text("You are authenticated. Welcome!"));
    }

    private boolean isFloodgatePlayer(UUID uuid) {
        if (Bukkit.getPluginManager().getPlugin("floodgate") == null
                && Bukkit.getPluginManager().getPlugin("Floodgate") == null) return false;
        try {
            Class<?> apiClass = Class.forName("org.geysermc.floodgate.api.FloodgateApi");
            Object api = apiClass.getMethod("getInstance").invoke(null);
            Object result = apiClass.getMethod("isFloodgatePlayer", UUID.class).invoke(api, uuid);
            return Boolean.TRUE.equals(result);
        } catch (ReflectiveOperationException ex) {
            getLogger().warning("Floodgate was detected but its API could not be queried; Bedrock auto-login skipped.");
            return false;
        }
    }

    private String lookupPremiumUuid(String playerName) {
        if (!premiumNameDetection) return null;
        long now = System.currentTimeMillis();
        ProfileCache cached = premiumProfiles.get(playerName.toLowerCase(Locale.ROOT));
        if (cached != null && cached.expiresAt() > now) return cached.uuid();
        HttpURLConnection connection = null;
        try {
            String encodedName = java.net.URLEncoder.encode(playerName, StandardCharsets.UTF_8);
            connection = (HttpURLConnection) URI.create("https://api.mojang.com/users/profiles/minecraft/" + encodedName).toURL().openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(2500);
            connection.setReadTimeout(2500);
            connection.setRequestProperty("User-Agent", "DialogAuth/1.1.0");
            int status = connection.getResponseCode();
            String uuid = null;
            if (status == 200) {
                String json = new String(connection.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                Matcher matcher = PROFILE_ID.matcher(json);
                if (matcher.find()) uuid = matcher.group(1).toLowerCase(Locale.ROOT);
            }
            // Cache positive and negative results briefly to avoid hitting Mojang on every join.
            premiumProfiles.put(playerName.toLowerCase(Locale.ROOT), new ProfileCache(uuid, now + (uuid == null ? 60_000L : 600_000L)));
            return uuid;
        } catch (Exception ex) {
            getLogger().fine("Mojang profile lookup unavailable for " + playerName + ": " + ex.getMessage());
            return null; // Network failures never grant premium auto-login.
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private String normalizeUuid(String uuid) { return uuid.replace("-", "").toLowerCase(Locale.ROOT); }

    private void showAuthDialog(Player player) {
        if (!player.isOnline() || isAuthenticated(player) || authCheckStarted.containsKey(player.getUniqueId())) return;
        String key = player.getName().toLowerCase(Locale.ROOT);
        boolean registered = users.contains(key + ".password");
        DialogInput passwordInput = DialogInput.text("password", Component.text(registered ? "Enter your password" : "Create a password"))
                .width(300).labelVisible(true).maxLength(128).build();
        ActionButton submit = ActionButton.builder(Component.text(registered ? "Login" : "Register"))
                .width(200)
                .action(DialogAction.customClick((view, audience) -> {
                    if (!(audience instanceof Player p) || !p.isOnline()) return;
                    String password = view.getText("password");
                    if (password == null || password.isBlank()) {
                        p.sendMessage(Component.text("Please enter a password."));
                        showAuthDialog(p); return;
                    }
                    if (registered) handleLogin(p, key, password);
                    else handleRegister(p, key, password);
                }, ClickCallback.Options.builder().uses(1).lifetime(ClickCallback.DEFAULT_LIFETIME).build()))
                .build();
        Dialog dialog = Dialog.create(builder -> builder.empty()
                .base(DialogBase.builder(Component.text(registered ? "DialogAuth | Login" : "DialogAuth | Register"))
                        .canCloseWithEscape(false)
                        .body(List.of(DialogBody.plainMessage(Component.text(registered
                                ? "Log in with the password you registered." : "Create a password to protect this username."))))
                        .inputs(List.of(passwordInput))
                        .build())
                .type(DialogType.multiAction(List.of(submit))));
        player.showDialog(dialog);
    }

    private void handleRegister(Player player, String key, String password) {
        if (users.contains(key + ".password")) { showAuthDialog(player); return; }
        if (password.length() < minPasswordLength) {
            player.sendMessage(Component.text("Password must be at least " + minPasswordLength + " characters."));
            showAuthDialog(player); return;
        }
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        users.set(key + ".uuid", player.getUniqueId().toString());
        users.set(key + ".salt", Base64.getEncoder().encodeToString(salt));
        users.set(key + ".password", hashPassword(password, salt));
        users.set(key + ".created", System.currentTimeMillis());
        saveUsers();
        markAuthenticated(player);
    }

    private void handleLogin(Player player, String key, String password) {
        String expectedUuid = users.getString(key + ".uuid", "");
        if (!expectedUuid.equals(player.getUniqueId().toString())) {
            player.kick(Component.text("This username is registered to a different UUID."));
            return;
        }
        try {
            byte[] salt = Base64.getDecoder().decode(users.getString(key + ".salt", ""));
            String expected = users.getString(key + ".password", "");
            if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    hashPassword(password, salt).getBytes(StandardCharsets.UTF_8))) {
                int count = attempts.merge(player.getUniqueId(), 1, Integer::sum);
                if (count >= maxAttempts) { player.kick(Component.text("Too many incorrect password attempts.")); return; }
                player.sendMessage(Component.text("Incorrect password. Attempts: " + count + "/" + maxAttempts));
                showAuthDialog(player); return;
            }
            markAuthenticated(player);
        } catch (Exception e) {
            getLogger().warning("Invalid password record for " + key);
            player.kick(Component.text("Account password data is invalid. Contact a server administrator."));
        }
    }

    private String hashPassword(String password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 210_000, 256);
        try {
            return Base64.getEncoder().encodeToString(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded());
        } catch (Exception e) { throw new IllegalStateException("Password hashing is unavailable", e); }
        finally { spec.clearPassword(); }
    }

    @EventHandler public void onMove(PlayerMoveEvent e) {
        if (!isAuthenticated(e.getPlayer()) && e.getTo() != null &&
                (e.getFrom().getX() != e.getTo().getX() || e.getFrom().getY() != e.getTo().getY() || e.getFrom().getZ() != e.getTo().getZ())) e.setCancelled(true);
    }
    @EventHandler public void onCommand(PlayerCommandPreprocessEvent e) {
        if (!isAuthenticated(e.getPlayer()) && !e.getMessage().equalsIgnoreCase("/dialogauth login")) e.setCancelled(true);
    }
    @EventHandler public void onChat(AsyncPlayerChatEvent e) { if (!isAuthenticated(e.getPlayer())) e.setCancelled(true); }
    @EventHandler public void onInteract(PlayerInteractEvent e) { if (!isAuthenticated(e.getPlayer())) e.setCancelled(true); }
    @EventHandler public void onDrop(PlayerDropItemEvent e) { if (!isAuthenticated(e.getPlayer())) e.setCancelled(true); }
    @EventHandler public void onPickup(PlayerAttemptPickupItemEvent e) { if (!isAuthenticated(e.getPlayer())) e.setCancelled(true); }
}
