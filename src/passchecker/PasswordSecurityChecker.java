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
    
    private List<String> arguments = new ArrayList<>();
    private List<String> mostKnownPasswords = new LinkedList<>();
    
    private String password;
    private final int MAX_LEN = 10;
    private String foundPassword;
    
    private long time;
    private long tries;
    
    private boolean found;
    
    private List<String> characters = new ArrayList<>();
    
    /**
     * Costruttore che istanzia un Oggetto di tipo PasswordSecurityChecker.
     * @param arguments argomenti passati da linea di comando. Il primo 
     * argomento è la password, gli altri verranno salvati nella lista arguments
     * e utilizzati per provare a scoprire la password (solo i primi 4 di essi).
     */
    public PasswordSecurityChecker(String[] arguments) 
        throws IllegalArgumentException{
        
        if(arguments.length >= 1){
            //password
            if(arguments[0].length() <= MAX_LEN){
                password = arguments[0];
            }else{
                String err1 = "Passare una password con lunghezza";
                String err2 = err1 + "minore di: " + MAX_LEN;
                throw new IllegalArgumentException(err2);
            }
            
            //password più conosciute
            loadMostKnownPasswords();
            
            //Primi 4 argomenti
            this.arguments = arrayToList(arguments);
            this.arguments.remove(0);
            if(this.arguments.size() >= 5){
                for(int i = 4;i < this.arguments.size();i++){
                    this.arguments.remove(i);
                }
            }
            
            //Caratteri per brute force
            String string = new String(IntStream.rangeClosed(33,255).toArray(),
                0,223);
            characters = arrayToList(string.split(""));
			
        }else{
            String err1 = "Passare un array contenente almeno un dato";
            throw new IllegalArgumentException(err1);
        }
    }
    
    @Override
    public String toString(){
        String pass = "Password: " + password + "\n";
        if(!arguments.isEmpty()){
            String args = "Argomenti:\n";
            for(int i = 0;i < arguments.size();i++){
                args += arguments.get(i) + " ";
            }
            return pass + args;
        }
        return pass;
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
            String path = "../data/100000-most-known-passwords.txt";
            String inputLine;
            InputStream in = getClass().getResourceAsStream(path);
            InputStreamReader isr = new InputStreamReader(in);
            BufferedReader reader = new BufferedReader(isr);
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
    private void printTries(){
        System.out.print("\r");
        System.out.print("Tries: " + tries);
        System.out.print("\r");
    }
    
    /**
     * Questo metodo serve a scoprire la password usando la lista di password 
     * più utilizzate al mondo.Mentre lavora stampa anche i tentativi e tempo
     * impiegato complessivamente dal programma.
     */
    protected void dictionaryDecode() {
        long start = System.currentTimeMillis();
        for(String s : mostKnownPasswords){
            tries++;
            
            if(s.equals(password)){
                foundPassword = s;
                found = true;
                break;
            }
            if(tries % 10000 == 0){
                printTries();
            }
        }
        long current = System.currentTimeMillis();
        time += current-start;
    }
    
    /**
     * Questo metodo serve a scoprire la password usando la lista di argomenti 
     * passata dall'utente.
     */
    protected void argumentsDecode(){
        long start = System.currentTimeMillis();
        for(String i : arguments){
            if(password.equals(i)){
                tries++;
                found = true;
                break;
            }
            for(String j : arguments){
                if(password.equals(i+j)){
                    tries++;
                    found = true;
                    break;
                }else if(password.equals(j+i)){
                    tries++;
                    found = true;
                    break;
                }else if(password.equals(i.toLowerCase()+j.toLowerCase())){
                    tries++;
                    found = true;
                    break;
                }else if(password.equals(j.toLowerCase()+i.toLowerCase())){
                    tries++;
                    found = true;
                    break;
                }else if(password.equals(i.toUpperCase()+j.toUpperCase())){
                    tries++;
                    found = true;
                    break;
                }else if(password.equals(j.toUpperCase()+i.toUpperCase())){
                    tries++;
                    found = true;
                    break;
                }
                tries += 6;
                if(tries % 1000 == 0){
                    printTries();
                }
            }
            tries++;
        }
        long current = System.currentTimeMillis();
        time += current-start;
    }
    
    /**
     * Questo metodo serve a scoprire la password usando un attacco brute force.
     * @param keys lettera da cui parte il brute force, in teoria dovrebbe venir
     * passato un "" all'inizoi.
     */
    public void bruteForceDecode(String keys){
        if(keys.length() < MAX_LEN){
            for(String c : characters){
                tries++;
                if(!found && (keys+c).equals(password)){
                    found = true;
                    foundPassword = keys+c;
                    break;
                }else if(!found){
                    bruteForceDecode(keys + c);
                    
                    if(tries % 100000 == 0){
                        printTries();
                    }
                }
            }
        }
    }
    
    public void finalPrint(){
        System.out.print("Password trovata: " + foundPassword);
        System.out.print(" Tentativi: " + tries + " Tempo: ");
        System.out.print(time);
    }
    
    public void findPassword(){
        argumentsDecode();
        System.out.print("");
        if(found){
            finalPrint();
            System.out.println();
        }else{
            dictionaryDecode();
            System.out.print("");
            if(found){
                finalPrint();
            }else{
                bruteForceDecode("");
                System.out.print("");
                if(found){
                    finalPrint();
                }
            }
        }
        /*if(arguments.isEmpty()){
            dictionaryDecode();
            System.out.print("");
            if(found){
                finalPrint();
            }else{
                bruteForceDecode("");
                System.out.print("");
                if(found){
                    finalPrint();
                    System.out.println();
                }
            }
        }else{
            argumentsDecode();
            System.out.print("");
            if(found){
                finalPrint();
                System.out.println();
            }else{
                dictionaryDecode();
                System.out.print("");
                if(found){
                    finalPrint();
                }else{
                    bruteForceDecode("");
                    System.out.print("");
                    if(found){
                        finalPrint();
                    }
                }
            }
        }*/
    }
    
    public static void main(String[] args) {
        PasswordSecurityChecker psc = new PasswordSecurityChecker(args);
        //psc.findPassword();
        //psc.dictionaryDecode();
        psc.bruteForceDecode("");
        if(psc.found){
            System.out.println("Found: " + psc.foundPassword);
        }else{
            System.out.println("Inculati");
        }
    }
}