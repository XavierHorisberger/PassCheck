package passchecker;

import java.io.BufferedReader;
import java.util.LinkedList;
import java.util.List;
import java.util.ArrayList;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * La classe PasswordSecurityChecker serve per cercare di forzare una password
 * passata dall'utente usando tre modi differeti: dictionary attack, brute force
 * e cercare di forzarla usando gli argomenti che l'utente passa insieme alla 
 * password.
 * @author Xavier Horisberger
 * @verions 30.09.2021
 */
public class PasswordSecurityChecker {
    
    private List<String> arguments  = new ArrayList<>();
    private List<String> mostKnownPasswords = new LinkedList<>();
    
    private String password;
    private String foundPassword;
    
    private long time;
    private long tries;
    
    private boolean found = false;
    
    private String[] characters;
    
    /**
     * Costruttore che istanzia un Oggetto di tipo PasswordSecurityChecker.
     * @param arguments argomenti passati da linea di comando. Il primo 
     * argomento è la password, gli altri verranno salvati nella lista arguments
     * e utilizzati per provare a scoprire la password (solo i primi 4 di essi).
     */
    public PasswordSecurityChecker(String[] arguments){
        if(arguments.length == 1){
            loadMostKnownPasswords();
            password = arguments[0];
            String string = new String(IntStream.rangeClosed(32, 255).toArray(), 0, 224);
            characters = string.split("");
			
        }else if(arguments.length >= 1){
            loadMostKnownPasswords();
            password = arguments[0];
            this.arguments = arrayToList(arguments);
            //rimozione di password dalla lista di argomenti
            this.arguments.remove(0);
            //rimozione di tutti gli argomnenti passati tranne i primi 4.
            if(this.arguments.size() >= 5){
                for(int i = 4;i < this.arguments.size();i++){
                    this.arguments.remove(i);
                }
            }
            String string = new String(IntStream.rangeClosed(32, 255).toArray(), 0, 224);
            characters = string.split("");
			
        }else{
            throw new IllegalArgumentException("Passare un array contenente almeno un dato");
        }
    }
    
    @Override
    public String toString(){
        String pass = "Password: " + password + "\n";
        String args = "Argomenti:\n";
        for(int i = 0;i < arguments.size();i++){
            args += arguments.get(i) + " ";
        }
        return pass + args;
    }
    
    /**
     * Questo metodo trasforma un array di stringhe in una lista di stringhe.
     * @param array array di stringhe da trasformare.
     * @return lista contenente gli stessi dati dell'array passato.
     */
    private List<String> arrayToList(String[] array){
        List<String> list = new LinkedList<>();
        list.addAll(Arrays.asList(array));
        return list;
    }
    
    /**
     * Questo metodo serve per inserire il contenuto del file 
     * 100000-most-known-passwords.txt in una lista. Questo file contiene le
     * 100000 password più utilizzate al mondo.
     */
    private void loadMostKnownPasswords(){
        try{
            String inputLine;
            InputStream in = getClass().getResourceAsStream("../data/100000-most-known-passwords.txt"); 
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            while ((inputLine = reader.readLine()) != null) {
                mostKnownPasswords.add(inputLine);
            }
            reader.close();
        }catch(IOException e){
            System.err.println("Error reading file");
        }
    }
    
    /**
     * Questo metodo serve a stampare i tentativi e tempo impiegati a scoprire
     * la password.
     */
    private void printTimeAndTries(){
        System.out.print("\r");
        System.out.print("Tries: " + tries + " Time: " + time + " ms");
        System.out.print("\r");
    }
    
    /**
     * Questo metodo serve a scoprire la password usando la lista di password 
     * più utilizzate al mondo.Mentre lavora stampa anche i tentativi e tempo
     * impiegato complessivamente dal programma.
     */
    protected void dictionaryDecode() {
        long start;
        long current;
        long end; 
        
        for(String s : mostKnownPasswords){
            tries++;
            
            start = System.currentTimeMillis();
            if(s.equals(password)){
                current = System.currentTimeMillis();
                end = current-start;
                time += end;
                foundPassword = s;
                found = true;
                break;
            }
            current = System.currentTimeMillis();
            end = current-start;
            time += end;
            
            if(tries % 18 == 0){
                printTimeAndTries();
            }
        }
    }
    
    /**
     * Questo metodo serve a scoprire la password usando la lista di argomenti 
     * passata dall'utente.
     */
    protected void argumentsDecode(){
        long start;
        long current;
        long end;
        
        for(String s : arguments){
            tries += 1;
            
            start = System.currentTimeMillis();
            if(s.equals(password)){
                foundPassword = s;
                found = true;
                current = System.currentTimeMillis();
                end = current-start;
                time += end;
                break;
            }
            current = System.currentTimeMillis();
            end = current-start;
            time += end;
            
            if(tries % 20 == 0){
                printTimeAndTries();
            }
        }
    }
    
    /**
     * Questo metodo serve a scoprire la password usando un attacco brute force.
     * @param key lettera da cui parte il brute force, in teoria dovrebbe venir
     * passato un "" all'inizoi.
     */
    protected void bruteForceDecode(String key){
        long start;
        long current;
        long end; 
        
        start = System.currentTimeMillis();
        for(String letter : characters){
            if(found){
                break;
            }else{
                tries++;
                if((key + letter).equals(password)){
                    found = true;
                    foundPassword = key + letter;
                    break;
                }else{
                    if(letter.equals(characters[characters.length-1])){
                        for(String letter2 : characters){
                            bruteForceDecode(key + letter2);
                        }
                    }
                }
            }
        }
        
        current = System.currentTimeMillis();
        end = current-start;
        time += end;
    }
    
    public void findPassword(){
        if(arguments.isEmpty()){
            dictionaryDecode();
            System.out.print("");
            if(found){
                System.out.print("Password trovata: " + foundPassword + " Tentativi: " + tries + " Tempo: " + time);
                System.out.println();
            }else{
                bruteForceDecode("");
                if(found){
                    System.out.print("Password trovata: " + foundPassword + " Tentativi: " + tries + " Tempo: " + time);
                    System.out.println();
                }
            }
        }else{
            argumentsDecode();
            System.out.print("");
            if(found){
                System.out.print("Password trovata: " + foundPassword + " Tentativi: " + tries + " Tempo: " + time);
                System.out.println();
            }else{
                dictionaryDecode();
                System.out.print("");
                if(found){
                    System.out.print("Password trovata: " + foundPassword + " Tentativi: " + tries + " Tempo: " + time);
                    System.out.println();
                }else{
                    bruteForceDecode("");
                    System.out.print("");
                    if(found){
                        System.out.print("Password trovata: " + foundPassword + " Tentativi: " + tries + " Tempo: " + time);
                        System.out.println();
                    }
                }
            }
        }
    }
    
    public static void main(String[] args) {
        PasswordSecurityChecker psc = new PasswordSecurityChecker(args);
        psc.findPassword();
    }
}