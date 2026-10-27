package com.taho.dialogauth;

import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import net.kyori.adventure.text.Component;
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
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class DialogAuth extends JavaPlugin implements Listener {
    private final Map<UUID, Long> authenticated = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> attempts = new ConcurrentHashMap<>();
    private final Map<UUID, Long> quitTimes = new ConcurrentHashMap<>();
    private File usersFile;
    private YamlConfiguration users;
    private long sessionMillis;
    private int maxAttempts;
    private int minPasswordLength;
    private BukkitTask reminderTask;

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
                String key = args[1].toLowerCase(java.util.Locale.ROOT);
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
            for (Player p : Bukkit.getOnlinePlayers()) if (!isAuthenticated(p)) showAuthDialog(p);
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
        attempts.remove(p.getUniqueId());
        long lastQuit = getConfig().getLong("sessions." + p.getUniqueId(), 0L);
        if (users.contains(p.getName().toLowerCase(java.util.Locale.ROOT)) && lastQuit > 0 && System.currentTimeMillis() - lastQuit < sessionMillis) {
            authenticated.put(p.getUniqueId(), System.currentTimeMillis());
        } else {
            authenticated.remove(p.getUniqueId());
        }
        Bukkit.getScheduler().runTaskLater(this, () -> { if (p.isOnline() && !isAuthenticated(p)) showAuthDialog(p); }, 5L);
    }
    @EventHandler public void onQuit(PlayerQuitEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        authenticated.remove(id);
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
        getConfig().set("sessions." + p.getUniqueId(), System.currentTimeMillis());
        saveConfig();
        p.closeDialog();
        p.sendMessage(Component.text("You are authenticated. Welcome!"));
    }

    private void showAuthDialog(Player player) {
        if (!player.isOnline() || isAuthenticated(player)) return;
        String key = player.getName().toLowerCase(java.util.Locale.ROOT);
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
                }))
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
            player.kick(Component.text("This username is registered to a different offline UUID."));
            return;
        }
        try {
            byte[] salt = Base64.getDecoder().decode(users.getString(key + ".salt", ""));
            String expected = users.getString(key + ".password", "");
            if (!MessageDigest.isEqual(expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    hashPassword(password, salt).getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
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