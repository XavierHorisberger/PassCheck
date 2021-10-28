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
 * password, ovvero: nome, cognome, data di nascita e una parola extra. Tentando
 * diverse combinazioni tra esse, per provare a forzare la password.
 * @author Xavier Horisberger
 * @verions 30.09.2021
 */
public class PasswordSecurityChecker {
    
    /*
        Ordine argomenti: Nome, Cognome, DataNasicta, ParolaExtra
        La data deve essere in questo formato: gg.mm.aaaa
    */
    private List<String> argumentCombos = new ArrayList<>();
    private List<String> arguments = new ArrayList<>();
    private List<String> mostKnownPasswords = new LinkedList<>();
    
    private String password;
    private final int MAX_LEN = 20;
    private String foundPassword;
    
    private long time;
    private long tries;
    private long oldTries;
    
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
            for(String i : this.arguments){
                this.argumentCombos.add(i);
                this.argumentCombos.add(i.toLowerCase());
                this.argumentCombos.add(i.toUpperCase());
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
        int incrementor = 10000;
        long start = System.currentTimeMillis();
        for(String s : mostKnownPasswords){
            tries++;
            
            if(s.equals(password)){
                foundPassword = s;
                found = true;
                return;
            }
            if(oldTries < incrementor && tries >= incrementor){
                incrementor += 10000;
                printTries();
            }
            oldTries = tries;
        }
        time += System.currentTimeMillis()-start;
    }
    
    /**
     * Questo metodo serve a scoprire la password usando un attacco brute force.
     * @param keys lettera da cui parte il brute force, in teoria dovrebbe venir
     * passato un "" all'inizoi.
     */
    public void bruteForceDecode(String keys){
        int incrementor = 100000;
        long start = System.currentTimeMillis();
        if(keys.length() < MAX_LEN){
            for(String c : characters){
                tries++;
                if(!found && (keys+c).equals(password)){
                    found = true;
                    foundPassword = keys+c;
                    return;
                }else if(!found){
                    bruteForceDecode(keys + c);
                    if(oldTries < incrementor && tries >= incrementor){
                        incrementor += 100000;
                        printTries();
                    }
                    oldTries = tries;
                }
            }
        }
        time += System.currentTimeMillis()-start;
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
    }
    
    //---------------------------------------------------------------------------------------------------------------------
    
    /**
     * Questo metodo prova a scoprire la password usando la lista di argomenti 
     * passata dall'utente.
     */
    protected void argumentsDecode(){
        if(arguments.isEmpty()){
            return;
        }
        String firstN = "";
        String firstC = "";
        if(arguments.size() >= 2){
            firstN = arguments.get(0).substring(0,1).toUpperCase();
            firstC = arguments.get(1).substring(0,1).toUpperCase();
        }else{
            firstN = arguments.get(0).substring(0,1).toUpperCase();
        }
        
        int incrementor = 100;
        long start = System.currentTimeMillis();
        for(String i : argumentCombos){
            if(password.equals(i)){
                tries++;
                found = true;
                foundPassword = i;
                return;
            }
            tries++;
            if(password.equals(firstN+i)){
                tries++;
                found = true;
                foundPassword = firstN+i;
                return;
            }
            tries++;
            if(password.equals(firstC+i)){
                tries++;
                found = true;
                foundPassword = firstC+i;
                return;
            }
            tries++;
            for(String j : argumentCombos){
                if(password.equals(i+j)){
                    tries++;
                    found = true;
                    foundPassword = i+j;
                    return;
                }
                tries++;
            }
            if(oldTries < incrementor && tries >= incrementor){
                incrementor += 100;
                printTries();
            }
            oldTries = tries;
        }
        
        /*
        
        //combinazioni specifiche con tutti i dati
        if(arguments.size() == 4 && !found){
            for(int i = 1;i <= 3;i++){
                tryPasswords(arguments.get(0),arguments.get(1),
                    arguments.get(3),i);
                if(found){
                    return;
                }
                tryPasswords(arguments.get(0),arguments.get(1),
                    arguments.get(3).toLowerCase(),i);
                if(found){
                    return;
                }
                tryPasswords(arguments.get(0),arguments.get(1),
                    arguments.get(3).toUpperCase(),i);
                if(found){
                    return;
                }
                if(oldTries < incrementor && tries >= incrementor){
                    incrementor += 100;
                    printTries();
                }
                oldTries = tries;
            }
        }
        
        
        
        //combinazioni specifiche con Nome, Cognome e Nascita
        if(arguments.size() >= 3 && !found){
            //estrazione anno da data o si tiene il dato di partenza se la data
            //non è formattata correttamente
            List<String> dates = arrayToList(arguments.get(2).split("[.]"));
            for(int i = 1;i <= 3;i++){
                if(!(dates.size() == 3)){
                    dates.add(arguments.get(2));
                    dates.add(arguments.get(2));
                }
                for(int j = 0;j < dates.size();j++){
                    if(found){
                        return;
                    }else{
                        tryPasswords(arguments.get(0),arguments.get(1),
                            dates.get(j),i);
                    }
                }
                if(oldTries < incrementor && tries >= incrementor){
                    incrementor += 100;
                    printTries();
                }
                oldTries = tries;
            }
        }
        
        //combinazioni specifiche tra nome e cognome
        if(arguments.size() >= 2 && !found){
            for(int i = 1;i <= 3;i++){
                for(int j = 0;j < argumentCombos.size()-1;j++){
                    String s5 = argumentCombos.get(0).substring(0, i)
                        .concat(argumentCombos.get(1).substring(0, i))
                        .concat(extra);

                    tryPasswords(arguments.get(0),arguments.get(1),"",i);
                    if(found){
                        return;
                    }
                    if(oldTries < incrementor && tries >= incrementor){
                        incrementor += 100;
                        printTries();
                    }
                    oldTries = tries;
                }
            }
        }*/
        
        time += System.currentTimeMillis()-start;
    }
    
    protected void tryPasswords(String first, String second, String extra, 
        int index){
        System.out.println(index);
        if(first.length() >= index && second.length() >= index){
            String s1 = first.substring(0, index)
                .concat(second.substring(0, index)).concat(extra);
            System.out.println(s1);
            if(s1.equals(password) ){
                tries++;
                found = true;
                foundPassword = s1;
                return;
            }
            tries++;
            String s2 = first.substring(0, index).toLowerCase()
                .concat(second.substring(0, index).toLowerCase()).concat(extra);
            System.out.println(s2);
            if(s2.equals(password) ){
                tries++;
                found = true;
                foundPassword = s2;
                return;
            }
            tries++;
            String s3 = first.substring(0, index).toUpperCase()
                .concat(second.substring(0, index).toUpperCase()).concat(extra);
            System.out.println(s3);
            if(s3.equals(password)){
                tries++;
                found = true;
                foundPassword = s3;
                return;
            }
            tries++;
            String s4 = first.substring(0, index).toLowerCase()
                .concat(second.substring(0, index).toUpperCase()).concat(extra);
            System.out.println(s4);
            if(s4.equals(password)){
                tries++;
                found = true;
                foundPassword = s4;
                return;
            }
            tries++;
            String s5 = first.substring(0, index).toUpperCase()
                .concat(second.substring(0, index).toLowerCase()).concat(extra);
            System.out.println(s5);
            if(s5.equals(password)){
                tries++;
                found = true;
                foundPassword = s5;
                return;
            }
            tries++;
        }
    }

    public static void main(String[] args) {
        PasswordSecurityChecker psc = new PasswordSecurityChecker(args);
        //psc.findPassword();
        psc.argumentsDecode();
        /*psc.bruteForceDecode("");*/
        if(psc.found){
            System.out.println("\rFound: " + psc.foundPassword + " Tries: " + psc.tries + " Time: " + psc.time);
        }else{
            System.out.println("\rInculati");
        }
        /*for(String s : psc.arguments){
            System.out.println(s);
        }*/
    }
}